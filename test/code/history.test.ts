import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { GitError } from '../../src/code/git.js';
import { scanHistory, type HistoryLimits } from '../../src/code/history.js';
import { fingerprint } from '../../src/code/patterns.js';
import { commitAll, git, gitInit, repoWith } from '../helpers/git.js';
import { FAKE } from '../helpers/secrets.js';
import { slowGitLog } from '../helpers/slow-git.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

const LIMITS: HistoryLimits = { maxCommits: 2000, maxDiffBytes: 20_000_000, timeoutMs: 60_000 };

function head(dir: string): string {
  return git(dir, 'rev-parse', 'HEAD').trim();
}

describe('scanHistory', () => {
  it('finds a secret that a later commit removed, naming the commit that added it', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'app.ts': `// header\nconst key = '${FAKE.awsKeyId}';\n` });
    const added = head(dir);
    await writeFiles(dir, { 'app.ts': "// header\nconst key = process.env.KEY;\n" });
    commitAll(dir, 'remove the key');

    const scan = await scanHistory(dir, LIMITS);
    expect(scan.hits).toEqual([{ sha: added, path: 'app.ts', line: 2, pattern: 'aws-access-key-id', fingerprint: fingerprint(FAKE.awsKeyId) }]);
    expect(scan.commits).toBe(2);
    expect(scan.stopped).toBeUndefined();
    expect(JSON.stringify(scan)).not.toContain(FAKE.awsKeyId);
  });

  it('reports a secret once, at the commit that added it, not again where a later commit removes it or leaves it in context', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'a.ts': `x\n${FAKE.githubToken}\ny\n` });
    const added = head(dir);
    await writeFiles(dir, { 'a.ts': `x\n${FAKE.githubToken}\ny\nz\n` });
    commitAll(dir, 'touch nearby');
    await writeFiles(dir, { 'a.ts': 'x\ny\nz\n' });
    commitAll(dir, 'remove');

    const scan = await scanHistory(dir, LIMITS);
    expect(scan.hits.map((h) => [h.sha, h.line, h.pattern])).toEqual([[added, 2, 'github-token']]);
  });

  it('scans only the high-confidence patterns, never the generic assignment heuristic', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'a.ts': `const config = { api_key: "${FAKE.genericValue}" };\n` });
    expect((await scanHistory(dir, LIMITS)).hits).toEqual([]);
  });

  it('numbers lines as the file had them in that commit', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'a.ts': 'one\ntwo\nthree\nfour\nfive\n' });
    await writeFiles(dir, { 'a.ts': `one\ntwo\nthree\nfour\n${FAKE.slackToken}\nfive\n` });
    commitAll(dir, 'add');
    const scan = await scanHistory(dir, LIMITS);
    expect(scan.hits.map((h) => h.line)).toEqual([5]);
  });

  it('scans an added line that itself starts with "++", which looks like a file header', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'a.txt': `++ ${FAKE.awsKeyId}\n` });
    expect((await scanHistory(dir, LIMITS)).hits.map((h) => [h.path, h.line])).toEqual([['a.txt', 1]]);
  });

  it('reads every ref: a secret on a branch that was never merged is found', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'a.ts': 'x\n' });
    git(dir, 'checkout', '-q', '-b', 'side');
    await writeFiles(dir, { 'leak.env': `TOKEN=${FAKE.githubToken}\n` });
    commitAll(dir, 'side work');
    git(dir, 'checkout', '-q', 'main');
    const scan = await scanHistory(dir, LIMITS);
    expect(scan.hits.map((h) => h.path)).toEqual(['leak.env']);
  });

  it('finds a secret in a deleted file and in a file whose name needs quoting', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'with space.txt': `${FAKE.stripeLiveKey}\n`, 'say "hi".txt': `${FAKE.googleApiKey}\n` });
    git(dir, 'rm', '-q', '-r', '.');
    commitAll(dir, 'delete everything');
    const scan = await scanHistory(dir, LIMITS);
    expect(scan.hits.map((h) => h.pattern).sort()).toEqual(['google-api-key', 'stripe-live-key']);
    expect(scan.hits.find((h) => h.pattern === 'stripe-live-key')?.path).toBe('with space.txt');
    expect(scan.hits.find((h) => h.pattern === 'google-api-key')?.path).toContain('say');
  });

  it('handles CRLF files', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'a.txt': `a\r\nurl: postgres://app:${FAKE.urlPassword}@db/app\r\n` });
    const scan = await scanHistory(dir, LIMITS);
    expect(scan.hits.map((h) => [h.line, h.pattern])).toEqual([[2, 'url-credentials']]);
  });

  it('never reads .secagent', async () => {
    const dir = await tempDir();
    await repoWith(dir, { '.secagent/evidence/x.json': `${FAKE.awsKeyId}\n`, 'ok.ts': 'x\n' });
    expect((await scanHistory(dir, LIMITS)).hits).toEqual([]);
  });

  it('a project directory below the repository root sees only its own files, with paths relative to it', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'other/leak.ts': `${FAKE.awsKeyId}\n`, 'app/src/leak.ts': `${FAKE.githubToken}\n` });
    const scan = await scanHistory(path.join(dir, 'app'), LIMITS);
    expect(scan.hits.map((h) => h.path)).toEqual(['src/leak.ts']);
  });

  it('an empty repository has nothing to scan and is not an error', async () => {
    const dir = await tempDir();
    gitInit(dir);
    const scan = await scanHistory(dir, LIMITS);
    expect(scan).toMatchObject({ hits: [], commits: 0, shallow: false, partial: false });
    expect(scan.stopped).toBeUndefined();
  });

  describe('limits', () => {
    async function manyCommits(n: number): Promise<string> {
      const dir = await tempDir();
      gitInit(dir);
      for (let i = 0; i < n; i += 1) {
        await writeFiles(dir, { [`f${i}.txt`]: `${i}\n` });
        commitAll(dir, `c${i}`);
      }
      return dir;
    }

    it('stops at maxCommits and says so, counting the commits it read', async () => {
      const dir = await manyCommits(4);
      const scan = await scanHistory(dir, { ...LIMITS, maxCommits: 2 });
      expect(scan.stopped).toBe('commits');
      expect(scan.commits).toBe(2);
    });

    it('does not claim a stop when the log has exactly maxCommits commits', async () => {
      const dir = await manyCommits(3);
      const scan = await scanHistory(dir, { ...LIMITS, maxCommits: 3 });
      expect(scan.stopped).toBeUndefined();
      expect(scan.commits).toBe(3);
    });

    it('stops at maxDiffBytes', async () => {
      const dir = await tempDir();
      await repoWith(dir, { 'big.txt': 'line of filler text\n'.repeat(2000) });
      const scan = await scanHistory(dir, { ...LIMITS, maxDiffBytes: 1000 });
      expect(scan.stopped).toBe('bytes');
    });

    it('stops at the timeout', async () => {
      const dir = await manyCommits(3);
      await slowGitLog();
      const scan = await scanHistory(dir, { ...LIMITS, timeoutMs: 100 });
      expect(scan.stopped).toBe('timeout');
    });

    it('keeps the hits it found before the cap', async () => {
      const dir = await tempDir();
      await repoWith(dir, { 'old.txt': `${FAKE.awsKeyId}\n` });
      for (let i = 0; i < 3; i += 1) {
        await writeFiles(dir, { [`f${i}.txt`]: `${i}\n` });
        commitAll(dir, `c${i}`);
      }
      const scan = await scanHistory(dir, { ...LIMITS, maxCommits: 2 });
      expect(scan.stopped).toBe('commits');
      expect(scan.hits).toEqual([]);
    });
  });

  describe('clones that lack history', () => {
    it('flags a shallow clone', async () => {
      const origin = await tempDir();
      await repoWith(origin, { 'a.txt': 'one\n' });
      await writeFiles(origin, { 'a.txt': 'two\n' });
      commitAll(origin, 'second');
      const parent = await tempDir();
      const clone = path.join(parent, 'clone');
      git(parent, 'clone', '-q', '--depth', '1', `file://${origin}`, clone);
      const scan = await scanHistory(clone, LIMITS);
      expect(scan.shallow).toBe(true);
      expect(scan.commits).toBe(1);
    });

    it('flags a partial clone and does not try to fetch what it lacks', async () => {
      const dir = await tempDir();
      await repoWith(dir, { 'a.txt': 'one\n' });
      git(dir, 'config', 'remote.origin.url', 'file:///nonexistent');
      git(dir, 'config', 'remote.origin.promisor', 'true');
      const scan = await scanHistory(dir, LIMITS);
      expect(scan.partial).toBe(true);
      expect(scan.shallow).toBe(false);
    });

    it('a complete clone is neither', async () => {
      const dir = await tempDir();
      await repoWith(dir, { 'a.txt': 'one\n' });
      expect(await scanHistory(dir, LIMITS)).toMatchObject({ shallow: false, partial: false });
    });
  });

  it('throws a GitError that names git, not a pass, outside a repository', async () => {
    const dir = await tempDir();
    await mkdir(path.join(dir, 'sub'));
    await expect(scanHistory(path.join(dir, 'sub'), LIMITS)).rejects.toBeInstanceOf(GitError);
  });
});
