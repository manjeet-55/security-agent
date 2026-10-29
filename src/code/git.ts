import { spawn } from 'node:child_process';

/** git is not installed (or not on PATH). */
export class GitMissingError extends Error {
  constructor() {
    super('git was not found on PATH');
    this.name = 'GitMissingError';
  }
}

/** git ran but failed; the message is safe to show (a fixed prefix plus the first line of git's own error). */
export class GitError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'GitError';
  }
}

export interface GitRun {
  /** null when git was killed (timeout or output cap). */
  code: number | null;
  stdout: Buffer;
  stderr: string;
  truncated: boolean;
  timedOut: boolean;
}

export interface GitOptions {
  /** Written to git's stdin; without it stdin is closed. */
  input?: string;
  /** Kill git once it has written this much to stdout. */
  maxBytes?: number;
  timeoutMs?: number;
}

/**
 * Settings that make git inert on an untrusted repository: no fsmonitor hook, no signature or colour decoration. They are passed
 * with -c, which outranks the repository's own config.
 */
const SAFE_CONFIG = ['core.quotepath=off', 'core.fsmonitor=false', 'log.showSignature=false', 'color.ui=never', 'core.pager=cat'];

/** The caller's environment minus every GIT_* variable (a hook may have set GIT_DIR), plus settings that keep git read-only and offline. */
export function gitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!k.startsWith('GIT_')) env[k] = v;
  return {
    ...env,
    LC_ALL: 'C',
    GIT_OPTIONAL_LOCKS: '0',
    GIT_TERMINAL_PROMPT: '0',
    GIT_NO_LAZY_FETCH: '1',
    GIT_PAGER: 'cat',
  };
}

export function gitArgs(args: readonly string[]): string[] {
  return [...SAFE_CONFIG.flatMap((c) => ['-c', c]), ...args];
}

export function firstLine(text: string, max = 200): string {
  return (text.split('\n').find((l) => l.trim() !== '') ?? '').trim().slice(0, max);
}

/** Runs git without a shell, with cwd = dir. Resolves with the exit status; rejects only when git cannot be started. */
export function runGit(dir: string, args: readonly string[], opts: GitOptions = {}): Promise<GitRun> {
  const maxBytes = opts.maxBytes ?? 64 * 1024 * 1024;
  const timeoutMs = opts.timeoutMs ?? 30_000;
  return new Promise((resolve, reject) => {
    const child = spawn('git', gitArgs(args), { cwd: dir, env: gitEnv(), stdio: [opts.input === undefined ? 'ignore' : 'pipe', 'pipe', 'pipe'] });
    const chunks: Buffer[] = [];
    let bytes = 0;
    let stderr = '';
    let truncated = false;
    let timedOut = false;
    const timer = setTimeout(() => {
      timedOut = true;
      child.kill('SIGKILL');
    }, timeoutMs);

    child.stdout?.on('data', (chunk: Buffer) => {
      if (truncated) return;
      bytes += chunk.length;
      if (bytes > maxBytes) {
        truncated = true;
        child.kill('SIGKILL');
        return;
      }
      chunks.push(chunk);
    });
    child.stderr?.on('data', (chunk: Buffer) => {
      if (stderr.length < 4096) stderr += chunk.toString('utf8');
    });
    if (opts.input !== undefined && child.stdin) {
      child.stdin.on('error', () => {});
      child.stdin.end(opts.input);
    }
    child.on('error', (e: NodeJS.ErrnoException) => {
      clearTimeout(timer);
      reject(e.code === 'ENOENT' ? new GitMissingError() : e);
    });
    child.on('close', (code) => {
      clearTimeout(timer);
      resolve({ code: truncated || timedOut ? null : code, stdout: Buffer.concat(chunks), stderr, truncated, timedOut });
    });
  });
}

export type RepoState = { state: 'repo' } | { state: 'none' } | { state: 'git_missing' } | { state: 'error'; reason: string };

/** Is `dir` inside a git work tree? Anything other than a clear yes or "not a git repository" is an error, not a no. */
export async function repoState(dir: string): Promise<RepoState> {
  let run: GitRun;
  try {
    run = await runGit(dir, ['rev-parse', '--is-inside-work-tree']);
  } catch (e) {
    if (e instanceof GitMissingError) return { state: 'git_missing' };
    return { state: 'error', reason: `git could not be started (${(e as NodeJS.ErrnoException).code ?? 'unknown error'})` };
  }
  const out = run.stdout.toString('utf8').trim();
  if (run.code === 0 && out === 'true') return { state: 'repo' };
  if (run.code === 0 && out === 'false') return { state: 'none' };
  if (run.code === 128 && /not a git repository/i.test(run.stderr)) return { state: 'none' };
  return { state: 'error', reason: `git exited with ${run.code ?? 'a timeout'}: ${firstLine(run.stderr) || 'no message'}` };
}

export type FileSelection = 'tracked' | 'tracked-and-untracked' | 'untracked' | 'ignored';

const LS_FILES: Record<FileSelection, string[]> = {
  tracked: ['ls-files', '-z'],
  'tracked-and-untracked': ['ls-files', '-z', '--cached', '--others', '--exclude-standard'],
  untracked: ['ls-files', '-z', '--others', '--exclude-standard'],
  // --directory collapses ignored directories (node_modules/) into one entry, which is dropped: nothing inside can be committed.
  ignored: ['ls-files', '-z', '--others', '--ignored', '--exclude-standard', '--directory'],
};

/** Paths git reports under `dir` (relative to it, posix), sorted and without duplicates. Throws GitError if git fails. */
export async function gitListFiles(dir: string, selection: FileSelection): Promise<string[]> {
  const run = await runGit(dir, LS_FILES[selection]);
  if (run.truncated) throw new GitError('git ls-files produced more output than the 64 MiB limit');
  if (run.timedOut) throw new GitError('git ls-files timed out');
  if (run.code !== 0) throw new GitError(`git ls-files exited with ${run.code}: ${firstLine(run.stderr) || 'no message'}`);
  const paths = run.stdout.toString('utf8').split('\0').filter((p) => p !== '' && !p.endsWith('/'));
  return [...new Set(paths)].sort();
}
