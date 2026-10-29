import { rmSync } from 'node:fs';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { onTestFinished } from 'vitest';

const removeAtExit = new Set<string>();

/**
 * A fresh directory under the OS temp dir, removed (with everything in it) when the calling test finishes. Outside a test (a hook,
 * or a script that imports the helpers) it is removed when the process exits instead.
 */
export async function tempDir(prefix = 'secagent-'): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), prefix));
  try {
    onTestFinished(() => rm(dir, { recursive: true, force: true }));
  } catch {
    if (removeAtExit.size === 0) process.once('exit', () => removeAtExit.forEach((d) => rmSync(d, { recursive: true, force: true })));
    removeAtExit.add(dir);
  }
  return dir;
}

export async function writeFiles(root: string, files: Record<string, string>): Promise<void> {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content);
  }
}
