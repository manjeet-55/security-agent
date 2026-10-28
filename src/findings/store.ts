import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { projectStateDir } from '../paths.js';
import { ScanRecordSchema, type ScanRecord } from './schema.js';

export class FindingsStore {
  readonly dir: string;

  constructor(projectDir: string) {
    this.dir = path.join(projectStateDir(projectDir), 'findings');
  }

  async latest(): Promise<ScanRecord | undefined> {
    let text: string;
    try {
      text = await readFile(path.join(this.dir, 'latest.json'), 'utf8');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw e;
    }
    return ScanRecordSchema.parse(JSON.parse(text));
  }

  async write(record: ScanRecord): Promise<void> {
    const valid = ScanRecordSchema.parse(record);
    const json = `${JSON.stringify(valid, null, 2)}\n`;
    await mkdir(path.join(this.dir, 'history'), { recursive: true });
    await writeFile(path.join(this.dir, 'history', `${valid.scanned_at.replace(/[-:]/g, '')}.json`), json, 'utf8');
    await writeFile(path.join(this.dir, 'latest.json'), json, 'utf8');
  }
}
