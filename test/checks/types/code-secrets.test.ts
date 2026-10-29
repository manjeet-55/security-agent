import { mkdir, symlink, writeFile } from 'node:fs/promises';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { fingerprint } from '../../../src/code/patterns.js';
import { codeSecretsCheck, codeSecretsParams } from '../../../src/checks/types/code-secrets.js';
import type { CheckOutput } from '../../../src/checks/check-type.js';
import { codeSubject, makeCtx } from '../../helpers/ctx.js';
import { commitAll, git, gitInit, repoWith } from '../../helpers/git.js';
import { FAKE, PLANTED_LINES } from '../../helpers/secrets.js';
import { tempDir, writeFiles } from '../../helpers/tmp.js';

type Rule = 'working_tree';

async function run(dir: string, ctx: Awaited<ReturnType<typeof makeCtx>>['ctx'], rule: Rule = 'working_tree'): Promise<CheckOutput> {
  return codeSecretsCheck.run(ctx, codeSubject(dir), codeSecretsParams.parse({ rule }), {} as never);
}

async function evidenceOf(dir: string, out: CheckOutput): Promise<{ data: Record<string, any> }> {
  return JSON.parse(readFileSync(path.join(dir, '.secagent', 'evidence', `${out.evidence_id}.json`), 'utf8'));
}

describe('code_secrets params', () => {
  it('needs a known rule', () => {
    expect(codeSecretsParams.safeParse({ rule: 'nope' }).success).toBe(false);
    expect(codeSecretsParams.parse({ rule: 'working_tree' })).toEqual({ rule: 'working_tree' });
  });
});

describe('code_secrets working_tree', () => {
  describe.each([
    ['a git repository', true],
    ['a plain directory', false],
  ])('in %s', (_name, isRepo) => {
    async function project(files: Record<string, string>, overrides: Record<string, unknown> = {}) {
      const made = await makeCtx({}, overrides);
      if (isRepo) gitInit(made.dir);
      await writeFiles(made.dir, files);
      if (isRepo) commitAll(made.dir);
      return made;
    }

    it.each(Object.entries(PLANTED_LINES))('fails on a planted %s, reporting file, line and fingerprint but not the value', async (id, line) => {
      const { ctx, dir } = await project({ 'src/app.ts': `// header\n${line}\n` });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('fail');
      expect(out.observed).toContain(`src/app.ts:2 ${id}`);
      expect(out.observed).toMatch(/\[[0-9a-f]{8}\]/);
      const ev = await evidenceOf(dir, out);
      expect(ev.data.hits).toContainEqual({ path: 'src/app.ts', line: 2, pattern: id, fingerprint: expect.stringMatching(/^[0-9a-f]{8}$/) });
    });

    it('passes on clean code and says what it scanned', async () => {
      const { ctx, dir } = await project({ 'src/app.ts': 'export const x = 1;\n', 'README.md': '# hi\n' });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('pass');
      expect(out.observed).toContain('2 file');
    });

    it('skips placeholders and lines marked secagent:ignore', async () => {
      const { ctx, dir } = await project({
        '.env.example': 'API_KEY="your_api_key_here_please"\nDB=postgres://user:password@db/app\n',
        'src/a.ts': `const id = '${FAKE.awsKeyId}'; // secagent:ignore\n`,
      });
      expect((await run(dir, ctx)).outcome).toBe('pass');
    });

    it('applies the generic pattern to code but not to docs and lockfiles; high-confidence patterns still apply everywhere', async () => {
      const generic = PLANTED_LINES['generic-secret-assignment'] ?? '';
      const { ctx, dir } = await project({
        'docs/guide.md': `${generic}\n`,
        'notes.txt': `${generic}\n`,
        'package-lock.json': `${generic}\n`,
        'src/real.ts': `${generic}\n`,
        'docs/leak.md': `token ${FAKE.githubToken}\n`,
      });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('fail');
      const hits = (await evidenceOf(dir, out)).data.hits as Array<{ path: string; pattern: string }>;
      expect(hits.map((h) => `${h.path} ${h.pattern}`)).toEqual(['docs/leak.md github-token', 'src/real.ts generic-secret-assignment']);
    });

    it('orders hits by path then line and deduplicates identical ones', async () => {
      const { ctx, dir } = await project({
        'b.ts': `x\n${FAKE.awsKeyId} ${FAKE.awsKeyId}\n`,
        'a.ts': `${FAKE.githubToken}\n\n${FAKE.awsKeyId}\n`,
      });
      const out = await run(dir, ctx);
      const hits = (await evidenceOf(dir, out)).data.hits as Array<{ path: string; line: number }>;
      expect(hits.map((h) => `${h.path}:${h.line}`)).toEqual(['a.ts:1', 'a.ts:3', 'b.ts:2']);
    });

    it('honours code.exclude', async () => {
      const { ctx, dir } = await project(
        { 'fixtures/leak.txt': `${FAKE.awsKeyId}\n`, 'src/ok.ts': 'x\n' },
        { code: { exclude: ['fixtures/'] } },
      );
      expect((await run(dir, ctx)).outcome).toBe('pass');
    });

    it('never reads or reports the .secagent directory', async () => {
      const { ctx, dir } = await project({ 'src/ok.ts': 'x\n' });
      await writeFiles(dir, { '.secagent/knowledge/notes.md': `${FAKE.awsKeyId}\n`, '.secagent/project-copy.txt': `${FAKE.githubToken}\n` });
      expect((await run(dir, ctx)).outcome).toBe('pass');
    });

    it('is unverifiable, not a pass, when a file is larger than max_file_bytes', async () => {
      const { ctx, dir } = await project({ 'small.ts': 'x\n', 'big.sql': `${'-- filler\n'.repeat(50)}` }, { code: { max_file_bytes: 100 } });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('1 file(s) larger than 100 bytes');
      expect(out.observed).toContain('big.sql');
      expect(out.observed).toContain('does not mean');
      const ev = await evidenceOf(dir, out);
      expect(ev.data.skipped.too_large).toEqual(['big.sql']);
    });

    it('is unverifiable when there are more files than max_files', async () => {
      const files = Object.fromEntries(Array.from({ length: 5 }, (_v, i) => [`f${i}.ts`, 'x\n']));
      const { ctx, dir } = await project(files, { code: { max_files: 3 } });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('max_files');
    });

    it('still fails when it found a secret but could not scan everything, and says so', async () => {
      const { ctx, dir } = await project({ 'a.ts': `${FAKE.awsKeyId}\n`, 'big.sql': 'x'.repeat(500) }, { code: { max_file_bytes: 100 } });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('fail');
      expect(out.observed).toContain('a.ts:1');
      expect(out.observed).toContain('Not everything was scanned');
    });

    it('is unverifiable when a file cannot be read', async () => {
      if (process.getuid?.() === 0) return; // root reads everything
      const { ctx, dir } = await project({ 'ok.ts': 'x\n', 'locked.ts': 'y\n' });
      const { chmodSync } = await import('node:fs');
      chmodSync(path.join(dir, 'locked.ts'), 0o000);
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('locked.ts');
    });

    it('skips binary files without calling them unverifiable', async () => {
      const { ctx, dir } = await project({ 'src/ok.ts': 'x\n' });
      await writeFile(path.join(dir, 'blob.dat'), Buffer.concat([Buffer.from([0, 1, 2, 3]), Buffer.from(FAKE.awsKeyId)]));
      await writeFile(path.join(dir, 'logo.png'), Buffer.from(FAKE.awsKeyId));
      if (isRepo) commitAll(dir);
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('pass');
    });

    it('does not follow symlinks, so nothing outside the project is read', async () => {
      const outside = await tempDir('secagent-outside-');
      await writeFiles(outside, { 'secret.txt': `${FAKE.awsKeyId}\n`, 'dir/deep.txt': `${FAKE.githubToken}\n` });
      const { ctx, dir } = await project({ 'src/ok.ts': 'x\n' });
      await symlink(path.join(outside, 'secret.txt'), path.join(dir, 'link.txt'));
      await symlink(path.join(outside, 'dir'), path.join(dir, 'linkdir'));
      if (isRepo) commitAll(dir);
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('pass');
    });
  });

  describe('file selection', () => {
    it('in a git repository scans tracked and untracked-not-ignored files, not ignored ones', async () => {
      const { ctx, dir } = await makeCtx();
      await repoWith(dir, { '.gitignore': 'ignored.ts\n', 'tracked.ts': 'x\n' });
      await writeFiles(dir, { 'untracked.ts': `${FAKE.awsKeyId}\n`, 'ignored.ts': `${FAKE.githubToken}\n` });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('fail');
      const ev = await evidenceOf(dir, out);
      expect(ev.data.mode).toBe('git');
      expect((ev.data.hits as Array<{ path: string }>).map((h) => h.path)).toEqual(['untracked.ts']);
    });

    it('in git mode does not skip tracked files under directories the walk would exclude', async () => {
      const { ctx, dir } = await makeCtx();
      await repoWith(dir, { 'dist/bundle.js': `${FAKE.awsKeyId}\n` });
      expect((await run(dir, ctx)).outcome).toBe('fail');
    });

    it('in a plain directory walks it with default excludes', async () => {
      const { ctx, dir } = await makeCtx();
      await writeFiles(dir, {
        'src/ok.ts': 'x\n',
        'node_modules/pkg/index.js': `${FAKE.awsKeyId}\n`,
        'dist/out.js': `${FAKE.awsKeyId}\n`,
        'build/out.js': `${FAKE.awsKeyId}\n`,
        'vendor/v.php': `${FAKE.awsKeyId}\n`,
        'coverage/c.json': `${FAKE.awsKeyId}\n`,
        '.next/cache.js': `${FAKE.awsKeyId}\n`,
        '.git/config': `${FAKE.awsKeyId}\n`,
        'app.min.js': `${FAKE.awsKeyId}\n`,
        'app.js.map': `${FAKE.awsKeyId}\n`,
        'yarn.lock': `${FAKE.awsKeyId}\n`,
      });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('pass');
      const ev = await evidenceOf(dir, out);
      expect(ev.data.mode).toBe('walk');
      expect(ev.data.files_scanned).toBe(1);
    });

    it('walk mode reports an unreadable directory as unverifiable', async () => {
      if (process.getuid?.() === 0) return;
      const { ctx, dir } = await makeCtx();
      await writeFiles(dir, { 'ok.ts': 'x\n', 'locked/a.ts': 'y\n' });
      const { chmodSync } = await import('node:fs');
      chmodSync(path.join(dir, 'locked'), 0o000);
      try {
        const out = await run(dir, ctx);
        expect(out.outcome).toBe('unverifiable');
        expect(out.observed).toContain('locked');
      } finally {
        chmodSync(path.join(dir, 'locked'), 0o755);
      }
    });

    it('a project directory below the repository root only scans its own files', async () => {
      const { ctx, dir } = await makeCtx();
      await repoWith(dir, { 'other/leak.ts': `${FAKE.awsKeyId}\n`, 'app/ok.ts': 'x\n' });
      const sub = path.join(dir, 'app');
      await mkdir(path.join(sub, '.secagent'), { recursive: true });
      const out = await run(sub, ctx);
      expect(out.outcome).toBe('pass');
    });
  });

  it('writes nothing but evidence and never the secret values', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, Object.fromEntries(Object.entries(PLANTED_LINES).map(([id, line]) => [`src/${id}.txt`, `${line}\n`])));
    const out = await run(dir, ctx);
    const blob = JSON.stringify(out) + JSON.stringify(await evidenceOf(dir, out));
    for (const v of [FAKE.awsKeyId, FAKE.githubToken, FAKE.slackToken, FAKE.stripeLiveKey, FAKE.googleApiKey, FAKE.jwt, FAKE.urlPassword, FAKE.genericValue, FAKE.privateKeyBody]) {
      expect(blob).not.toContain(v);
    }
    expect(blob).toContain(fingerprint(FAKE.awsKeyId));
    expect(git(dir, 'status', '--porcelain')).toBe('?? .secagent/\n');
  });
});
