import { execFileSync } from 'node:child_process';
import { chmod, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { onTestFinished, vi } from 'vitest';
import { tempDir } from './tmp.js';

/**
 * Puts a `git` ahead of the real one on PATH that hangs on `git log` and passes every other command through, so a test can hit the
 * history time limit without racing a fast process. Restored when the calling test finishes.
 */
export async function slowGitLog(): Promise<void> {
  const real = execFileSync('sh', ['-c', 'command -v git'], { encoding: 'utf8' }).trim();
  const dir = await tempDir('secagent-slowgit-');
  const script = path.join(dir, 'git');
  await writeFile(script, `#!/bin/sh\ncase " $* " in *" log "*) exec sleep 30 ;; esac\nexec '${real}' "$@"\n`);
  await chmod(script, 0o755);
  vi.stubEnv('PATH', `${dir}:${process.env.PATH ?? ''}`);
  onTestFinished(() => {
    vi.unstubAllEnvs();
  });
}
