import { createHash, randomBytes } from 'node:crypto';
import { mkdir, readFile, rename, unlink, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';
import { ObservationError } from '../checks/errors.js';
import type { Freshness } from './types.js';

const DAY = 86_400_000;
export const TTL = { kev: DAY, osv: 3 * DAY, ubuntu: 3 * DAY } as const;
/** A cached copy older than this is never served in place of a failed refresh. */
export const MAX_STALE_MS = 30 * DAY;
/** A `fetched_at` further than this in the future is clock skew or tampering and counts as expired. */
const MAX_FUTURE_MS = 3_600_000;


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
  private used: Freshness | undefined;

  constructor(
    readonly dir: string = defaultCacheDir(),
    private readonly now: () => Date = () => new Date(),
  ) {}

  /** Freshness of everything served since the last call (oldest `as_of`, OR of `stale`), then resets. */
  freshness(): Freshness | undefined {
    const f = this.used;
    this.used = undefined;
    return f;
  }

  /** Registers `c` as used by the current call; also for results a client memoises in memory. */
  record<T>(c: Cached<T>): Cached<T> {
    const prev = this.used;
    this.used = {
      as_of: prev === undefined || Date.parse(c.fetched_at) < Date.parse(prev.as_of) ? c.fetched_at : prev.as_of,
      stale: (prev?.stale ?? false) || c.stale,
    };
    return c;
  }

  async getOrFetch<T>(source: string, key: string, ttlMs: number, fetcher: () => Promise<T>): Promise<Cached<T>> {
    const file = path.join(this.dir, source, `${createHash('sha256').update(key).digest('hex').slice(0, 32)}.json`);
    const cached = await this.read<T>(file, key);
    const now = this.now();
    const age = cached ? now.getTime() - Date.parse(cached.fetched_at) : Number.NaN;
    if (cached && age < ttlMs && age >= -MAX_FUTURE_MS) return this.record({ ...cached, stale: false });
    let value: T;
    try {
      value = await fetcher();
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      if (cached) {
        if (age >= -MAX_FUTURE_MS && age <= MAX_STALE_MS) return this.record({ ...cached, stale: true });
        const why = Number.isNaN(age) || age < 0 ? `its timestamp ${cached.fetched_at} is not usable` : `it is ${Math.floor(age / DAY)} days old (limit ${MAX_STALE_MS / DAY})`;
        throw new ObservationError('ADVISORY_UNAVAILABLE', `${source} advisories could not be refreshed (${reason}) and the cached copy is too old to use: ${why}`);
      }
      throw new ObservationError('ADVISORY_UNAVAILABLE', `${source} advisories are unavailable and nothing is cached: ${reason}`);
    }
    const fetched_at = now.toISOString();
    await this.write(file, { key, fetched_at, value });
    return this.record({ value, fetched_at, stale: false });
  }

  /** Best-effort: a cache that cannot be written must never discard a successful fetch. */
  private async write(file: string, entry: { key: string; fetched_at: string; value: unknown }): Promise<void> {
    const tmp = `${file}.${process.pid}.${randomBytes(6).toString('hex')}.tmp`;
    try {
      await mkdir(path.dirname(file), { recursive: true });
      await writeFile(tmp, JSON.stringify(entry), 'utf8');
      await rename(tmp, file);
    } catch {
      await unlink(tmp).catch(() => undefined);
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
