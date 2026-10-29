import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { onTestFinished } from 'vitest';

/** A fresh directory under the OS temp dir, removed (with everything in it) when the calling test finishes. Call it from inside a test. */
export async function tempDir(prefix = 'secagent-'): Promise<string> {
  const dir = await mkdtemp(path.join(os.tmpdir(), prefix));
  onTestFinished(() => rm(dir, { recursive: true, force: true }));
  return dir;
}

export async function writeFiles(root: string, files: Record<string, string>): Promise<void> {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content);
  }
}
