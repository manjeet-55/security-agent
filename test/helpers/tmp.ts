import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export function tempDir(prefix = 'secagent-'): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function writeFiles(root: string, files: Record<string, string>): Promise<void> {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content);
  }
}
