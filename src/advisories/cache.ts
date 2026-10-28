import { createHash } from 'node:crypto';
import { mkdir, readFile, rename, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ObservationError } from '../checks/errors.js';

const DAY = 86_400_000;
export const TTL = { kev: DAY, osv: 3 * DAY, ubuntu: 3 * DAY } as const;

export interface Cached<T> {
  value: T;
  fetched_at: string;
  stale: boolean;
}

export function defaultCacheDir(): string {
  return process.env.SECAGENT_CACHE_DIR ?? path.join(os.homedir(), '.cache', 'secagent', 'advisories');
}

/** File cache per source. Fresh entries are served as-is; on fetch failure a stale entry is served; with none, ADVISORY_UNAVAILABLE. */
export class AdvisoryCache {
  constructor(
    readonly dir: string = defaultCacheDir(),
    private readonly now: () => Date = () => new Date(),
  ) {}

  async getOrFetch<T>(source: string, key: string, ttlMs: number, fetcher: () => Promise<T>): Promise<Cached<T>> {
    const file = path.join(this.dir, source, `${createHash('sha256').update(key).digest('hex').slice(0, 32)}.json`);
    const cached = await this.read<T>(file, key);
    const now = this.now();
    if (cached && now.getTime() - Date.parse(cached.fetched_at) < ttlMs) return { ...cached, stale: false };
    try {
      const value = await fetcher();
      const fetched_at = now.toISOString();
      await mkdir(path.dirname(file), { recursive: true });
      const tmp = `${file}.${process.pid}.tmp`;
      await writeFile(tmp, JSON.stringify({ key, fetched_at, value }), 'utf8');
      await rename(tmp, file);
      return { value, fetched_at, stale: false };
    } catch (e) {
      if (cached) return { ...cached, stale: true };
      const reason = e instanceof Error ? e.message : String(e);
      throw new ObservationError('ADVISORY_UNAVAILABLE', `${source} advisories are unavailable and nothing is cached: ${reason}`);
    }
  }

  private async read<T>(file: string, key: string): Promise<{ value: T; fetched_at: string } | undefined> {
    try {
      const entry = JSON.parse(await readFile(file, 'utf8')) as { key?: string; fetched_at?: string; value?: T };
      if (entry.key !== key || typeof entry.fetched_at !== 'string' || !('value' in entry)) return undefined;
      return { value: entry.value as T, fetched_at: entry.fetched_at };
    } catch {
      return undefined;
    }
  }
}
