import { execFileSync } from 'node:child_process';
import { writeFiles } from './tmp.js';

/** Git for tests: no shell, no inherited GIT_* variables (a hook may set them), identity passed with -c. */
export function git(dir: string, ...args: string[]): string {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_')));
  return execFileSync('git', ['-c', 'user.name=Test', '-c', 'user.email=test@example.com', '-c', 'commit.gpgsign=false', ...args], {
    cwd: dir,
    env: { ...env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  });
}

export function gitInit(dir: string): void {
  git(dir, 'init', '-q', '-b', 'main');
}

export function commitAll(dir: string, message = 'commit'): void {
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', message);
}

/** A real git repository in `dir` holding `files`, committed. */
export async function repoWith(dir: string, files: Record<string, string>): Promise<void> {
  gitInit(dir);
  await writeFiles(dir, files);
  commitAll(dir, 'initial');
}
