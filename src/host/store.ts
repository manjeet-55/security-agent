import { mkdir, readdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { ObservationError } from '../checks/errors.js';
import { projectStateDir } from '../paths.js';
import { decodeSnapshot, SnapshotEnvelopeSchema, type HostSnapshot } from './snapshot.js';

export const MAX_SNAPSHOT_AGE_DAYS = 7;

/** How far ahead of the clock a snapshot's collected_at may be before it is rejected as bogus. */
export const MAX_FUTURE_SKEW_MS = 3_600_000;

/** `future` = collected_at is more than an hour ahead of `now`; `stale` = older than MAX_SNAPSHOT_AGE_DAYS. */
export function snapshotFreshness(collectedAt: string, now: Date): { state: 'fresh' | 'stale' | 'future'; ageDays: number } {
  const ageMs = now.getTime() - Date.parse(collectedAt);
  const ageDays = ageMs / 86_400_000;
  if (-ageMs > MAX_FUTURE_SKEW_MS) return { state: 'future', ageDays };
  return { state: ageDays > MAX_SNAPSHOT_AGE_DAYS ? 'stale' : 'fresh', ageDays };
}

export function assertHostName(host: string): void {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(host)) throw new ObservationError('SNAPSHOT_INVALID', `Invalid host name "${host}"`);
}

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

  constructor(
    projectDir: string,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.dir = path.join(projectStateDir(projectDir), 'hosts');
  }

  async add(host: string, text: string): Promise<StoredSnapshot> {
    assertHostName(host);
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch (e) {
      throw new ObservationError('SNAPSHOT_INVALID', `Snapshot is not JSON: ${(e as Error).message}`);
    }
    const snapshot = decodeSnapshot(raw);
    if (Date.parse(snapshot.collected_at) - this.now().getTime() > MAX_FUTURE_SKEW_MS) {
      throw new ObservationError('SNAPSHOT_INVALID', `Snapshot collected_at ${snapshot.collected_at} is in the future; check the clock on the host.`);
    }
    const file = path.join(this.dir, host, `${snapshot.collected_at.replace(/[-:]/g, '')}.json`);
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, `${JSON.stringify(SnapshotEnvelopeSchema.parse(raw))}\n`, 'utf8');
    return { snapshot, file };
  }

  /**
   * The newest snapshot for a host. A file dated more than an hour ahead of the clock is bogus (wrong clock on the host, or a
   * tampered file) and is skipped; if nothing else is stored, the error names the file to delete.
   */
  async latest(host: string): Promise<StoredSnapshot | undefined> {
    assertHostName(host);
    let names: string[];
    try {
      names = await readdir(path.join(this.dir, host));
    } catch {
      return undefined;
    }
    const now = this.now().getTime();
    const future: Array<{ file: string; collected_at: string }> = [];
    let best: StoredSnapshot | undefined;
    for (const name of names.filter((n) => n.endsWith('.json'))) {
      const file = path.join(this.dir, host, name);
      try {
        const snapshot = decodeSnapshot(JSON.parse(await readFile(file, 'utf8')));
        const at = Date.parse(snapshot.collected_at);
        if (at - now > MAX_FUTURE_SKEW_MS) future.push({ file, collected_at: snapshot.collected_at });
        // By time, not by text: '...:46Z' sorts after '...:46.500Z' as a string although it is earlier.
        else if (!best || at > Date.parse(best.snapshot.collected_at)) best = { snapshot, file };
      } catch {
        // Unreadable or invalid snapshot files are ignored; `snapshot add` validates new ones.
      }
    }
    if (!best && future.length > 0) {
      const listed = future.map((f) => `${f.file} (dated ${f.collected_at})`).join(', ');
      throw new ObservationError(
        'SNAPSHOT_INVALID',
        `The only snapshot(s) for host "${host}" are dated in the future: ${listed}. Check the clock on the host, delete the file(s) and re-run the collector.`,
      );
    }
    return best;
  }
}
