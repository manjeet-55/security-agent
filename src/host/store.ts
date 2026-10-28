import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ObservationError } from '../checks/errors.js';
import { projectStateDir } from '../paths.js';
import { decodeSnapshot, SnapshotEnvelopeSchema, type HostSnapshot } from './snapshot.js';

export const MAX_SNAPSHOT_AGE_DAYS = 7;

export interface StoredSnapshot {
  snapshot: HostSnapshot;
  file: string;
}

export interface SnapshotReader {
  latest(host: string): Promise<StoredSnapshot | undefined>;
}

/** Collector outputs under .secagent/hosts/<host>/<collected_at>.json (git-ignored). */
export class SnapshotStore implements SnapshotReader {
  readonly dir: string;

  constructor(projectDir: string) {
    this.dir = path.join(projectStateDir(projectDir), 'hosts');
  }

  async add(host: string, text: string): Promise<StoredSnapshot> {
    if (!/^[a-z0-9][a-z0-9-]*$/.test(host)) throw new ObservationError('SNAPSHOT_INVALID', `Invalid host name "${host}"`);
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch (e) {
      throw new ObservationError('SNAPSHOT_INVALID', `Snapshot is not JSON: ${(e as Error).message}`);
    }
    const snapshot = decodeSnapshot(raw);
    const file = path.join(this.dir, host, `${snapshot.collected_at.replace(/[-:]/g, '')}.json`);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, `${JSON.stringify(SnapshotEnvelopeSchema.parse(raw))}\n`, 'utf8');
    return { snapshot, file };
  }

  async latest(host: string): Promise<StoredSnapshot | undefined> {
    let names: string[];
    try {
      names = await readdir(path.join(this.dir, host));
    } catch {
      return undefined;
    }
    let best: StoredSnapshot | undefined;
    for (const name of names.filter((n) => n.endsWith('.json'))) {
      const file = path.join(this.dir, host, name);
      try {
        const snapshot = decodeSnapshot(JSON.parse(await readFile(file, 'utf8')));
        if (!best || snapshot.collected_at > best.snapshot.collected_at) best = { snapshot, file };
      } catch {
        // Unreadable or invalid snapshot files are ignored; `snapshot add` validates new ones.
      }
    }
    return best;
  }
}
