import { spawn } from 'node:child_process';
import { StringDecoder } from 'node:string_decoder';
import { SECAGENT_DIRNAME } from '../paths.js';
import { firstLine, gitArgs, gitEnv, GitError, GitMissingError, runGit } from './git.js';
import { HIGH_CONFIDENCE_PATTERN_IDS, scanLine } from './patterns.js';

export interface HistoryLimits {
  maxCommits: number;
  maxDiffBytes: number;
  timeoutMs: number;
}

export interface HistoryHit {
  /** Full commit id. */
  sha: string;
  path: string;
  /** Line number in the file as that commit left it. */
  line: number;
  pattern: string;
  fingerprint: string;
}

export interface HistoryScan {
  hits: HistoryHit[];
  commits: number;
  diffBytes: number;
  /** Why reading stopped before the end of the log, if it did. */
  stopped?: 'commits' | 'bytes' | 'timeout';
  /** The clone has only part of the history, so older commits (and their secrets) are absent. */
  shallow: boolean;
  /** Objects may be missing (a partial clone), and git must not fetch them: this scan never uses the network. */
  partial: boolean;
}

/** Most hits kept in memory; the count of further ones is still reported. */
const HIT_CAP = 5000;
const COMMIT_MARK = '\u0001';
const HUNK = /^@@ -\d+(?:,(\d+))? \+(\d+)(?:,(\d+))? @@/;

/**
 * The file a "+++ " header names, or undefined for a deletion. Git wraps a path with a quote, backslash or control character in
 * double quotes and C escapes ("b/say \"hi\".txt"); that form is kept as written rather than dropped, so the file is still scanned.
 */
function diffTargetPath(header: string): string | undefined {
  const target = header.split('\t')[0] ?? '';
  if (target === '/dev/null') return undefined;
  if (target.startsWith('b/')) return target.slice(2);
  if (target.startsWith('"b/') && target.endsWith('"')) return target.slice(3, -1);
  return undefined;
}

/**
 * Reads `git log -p` one line at a time and scans only the lines a commit added. Hunk headers say how many old and new lines
 * follow, which is how an added line that starts with "++" is told apart from a "+++" file header.
 */
class AddedLineScanner {
  readonly hits: HistoryHit[] = [];
  hitCount = 0;
  commits = 0;
  private sha = '';
  private path: string | undefined;
  private oldLeft = 0;
  private newLeft = 0;
  private newLine = 0;

  /** Returns true when a new commit starts. */
  feed(line: string): boolean {
    if (line.startsWith(COMMIT_MARK)) {
      this.commits += 1;
      this.sha = line.slice(1).trim();
      this.path = undefined;
      this.oldLeft = 0;
      this.newLeft = 0;
      return true;
    }
    if (this.oldLeft > 0 || this.newLeft > 0) {
      const c = line[0];
      if (c === '+') {
        this.newLeft -= 1;
        this.added(line.slice(1));
        this.newLine += 1;
      } else if (c === '-') {
        this.oldLeft -= 1;
      } else if (c === ' ' || line === '') {
        this.oldLeft -= 1;
        this.newLeft -= 1;
        this.newLine += 1;
      } // "\ No newline at end of file" consumes nothing
      return false;
    }
    if (line.startsWith('diff --git ')) {
      this.path = undefined;
    } else if (line.startsWith('+++ ')) {
      this.path = diffTargetPath(line.slice(4));
    } else {
      const m = HUNK.exec(line);
      if (m) {
        this.oldLeft = m[1] === undefined ? 1 : Number(m[1]);
        this.newLeft = m[3] === undefined ? 1 : Number(m[3]);
        this.newLine = Number(m[2]);
      }
    }
    return false;
  }

  private added(text: string): void {
    if (this.path === undefined) return;
    const content = text.endsWith('\r') ? text.slice(0, -1) : text;
    for (const h of scanLine(content, { generic: false })) {
      this.hitCount += 1;
      if (this.hits.length < HIT_CAP) this.hits.push({ sha: this.sha, path: this.path, line: this.newLine, pattern: h.pattern, fingerprint: h.fingerprint });
    }
  }
}

async function gitFlag(dir: string, args: readonly string[]): Promise<boolean> {
  const run = await runGit(dir, args);
  return run.code === 0 && run.stdout.toString('utf8').trim() === 'true';
}

/**
 * Scans the added lines of every commit reachable from any ref (`git log --all -p`) with the high-confidence patterns, newest first,
 * within the limits. Never follows a promisor remote. Throws GitMissingError / GitError when git cannot do it.
 */
export async function scanHistory(dir: string, limits: HistoryLimits): Promise<HistoryScan> {
  const shallow = await gitFlag(dir, ['rev-parse', '--is-shallow-repository']);
  const promisor = await runGit(dir, ['config', '--get-regexp', '^(remote\\..*\\.promisor|extensions\\.partialclone)$']);
  const partial = promisor.code === 0;

  const args = gitArgs([
    'log',
    '--all',
    '-p',
    '--no-color',
    '--no-textconv',
    '--no-ext-diff',
    '--no-renames',
    '--relative',
    '--src-prefix=a/',
    '--dst-prefix=b/',
    '--format=%x01%H',
    `--max-count=${limits.maxCommits + 1}`,
    '--',
    '.',
    `:(exclude)${SECAGENT_DIRNAME}`,
  ]);

  return new Promise<HistoryScan>((resolve, reject) => {
    const child = spawn('git', args, { cwd: dir, env: gitEnv(), stdio: ['ignore', 'pipe', 'pipe'] });
    const scanner = new AddedLineScanner();
    const decoder = new StringDecoder('utf8');
    let pending = '';
    let bytes = 0;
    let stopped: HistoryScan['stopped'];
    let stderr = '';

    const stop = (why: NonNullable<HistoryScan['stopped']>): void => {
      if (stopped) return;
      stopped = why;
      child.kill('SIGKILL');
    };
    const timer = setTimeout(() => stop('timeout'), limits.timeoutMs);

    const feedLines = (text: string): void => {
      pending += text;
      let nl = pending.indexOf('\n');
      while (nl !== -1 && !stopped) {
        const line = pending.slice(0, nl);
        pending = pending.slice(nl + 1);
        if (scanner.feed(line) && scanner.commits > limits.maxCommits) stop('commits');
        nl = pending.indexOf('\n');
      }
    };

    child.stdout.on('data', (chunk: Buffer) => {
      if (stopped) return;
      bytes += chunk.length;
      if (bytes > limits.maxDiffBytes) {
        stop('bytes');
        return;
      }
      feedLines(decoder.write(chunk));
    });
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.length < 4096) stderr += chunk.toString('utf8');
    });
    child.on('error', (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(e.code === 'ENOENT' ? new GitMissingError() : e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      if (!stopped) {
        feedLines(`${decoder.end()}\n`);
        if (code !== 0) {
          reject(new GitError(`git log exited with ${code}: ${firstLine(stderr) || 'no message'}`));
          return;
        }
      }
      const commits = stopped === 'commits' ? limits.maxCommits : scanner.commits;
      // The commit that tripped the cap was only a marker; any hit it produced cannot exist, because scanning stopped at its marker.
      resolve({
        hits: scanner.hits,
        commits,
        diffBytes: bytes,
        ...(stopped ? { stopped } : {}),
        shallow,
        partial,
      });
    });
  });
}

export { HIGH_CONFIDENCE_PATTERN_IDS };
