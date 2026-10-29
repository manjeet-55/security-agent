import { access, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { tempDir, writeFiles } from './tmp.js';

describe('tempDir', () => {
  // Tests in a file run in order: the second one looks at what the first left behind.
  let made: string | undefined;

  it('creates a directory that the test can fill', async () => {
    made = await tempDir();
    await writeFiles(made, { 'a/b/c.txt': 'x' });
    await writeFile(path.join(made, 'top.txt'), 'y');
    await expect(access(path.join(made, 'a', 'b', 'c.txt'))).resolves.toBeUndefined();
  });

  it('removes the directory, contents included, when the test that made it is over', async () => {
    expect(made).toBeDefined();
    await expect(access(made as string)).rejects.toMatchObject({ code: 'ENOENT' });
  });
});
