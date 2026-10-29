import { AsyncLocalStorage } from 'node:async_hooks';
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

/** The advisory data read inside one `track` call; a nested call also reports to the scope around it. */
interface Scope {
  used: Freshness | undefined;
  parent: Scope | undefined;
}

/**
 * One store for every AdvisoryCache, not one per cache: Advisories composed from several caches (one source from each) must
 * still report their reads into the scope of whichever `track` the caller used.
 */
const scopes = new AsyncLocalStorage<Scope>();

/**
 * Sources whose staleness does not make a result stale. The CISA KEV catalog only says which CVEs are exploited; it never
 * changes a version comparison, so an old or unreachable catalog must neither block a dismissal nor turn a pass into
 * unverifiable. Its fetch time still counts toward `as_of`, so the age is reported.
 */
const NOT_VERSION_DATA = new Set(['kev']);

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

  /**
   * Runs `fn` and reports the freshness of exactly the advisory data read inside its async scope: the oldest `as_of` (KEV
   * included) and the OR of `stale` over everything except KEV, across every `getOrFetch` (and `record`) it awaits, on any
   * cache. Concurrent calls each get their own scope, so one caller's reads never show up in another's result.
   */
  async track<T>(fn: () => Promise<T>): Promise<{ value: T; freshness: Freshness | undefined }> {
    const scope: Scope = { used: undefined, parent: scopes.getStore() };
    const value = await scopes.run(scope, fn);
    return { value, freshness: scope.used };
  }

  /** Registers `c`, read from `source`, with the surrounding `track` scope, if any; also for results a client memoises in memory. */
  record<T>(c: Cached<T>, source: string): Cached<T> {
    const stale = c.stale && !NOT_VERSION_DATA.has(source);
    for (let scope = scopes.getStore(); scope !== undefined; scope = scope.parent) {
      const prev = scope.used;
      scope.used = {
        as_of: prev === undefined || Date.parse(c.fetched_at) < Date.parse(prev.as_of) ? c.fetched_at : prev.as_of,
        stale: (prev?.stale ?? false) || stale,
      };
    }
    return c;
  }

  async getOrFetch<T>(source: string, key: string, ttlMs: number, fetcher: () => Promise<T>): Promise<Cached<T>> {
    const file = path.join(this.dir, source, `${createHash('sha256').update(key).digest('hex').slice(0, 32)}.json`);
    const cached = await this.read<T>(file, key);
    const now = this.now();
    const age = cached ? now.getTime() - Date.parse(cached.fetched_at) : Number.NaN;
    if (cached && age < ttlMs && age >= -MAX_FUTURE_MS) return this.record({ ...cached, stale: false }, source);
    let value: T;
    try {
      value = await fetcher();
    } catch (e) {
      const reason = e instanceof Error ? e.message : String(e);
      if (cached) {
        if (age >= -MAX_FUTURE_MS && age <= MAX_STALE_MS) return this.record({ ...cached, stale: true }, source);
        const why = Number.isNaN(age) || age < 0 ? `its timestamp ${cached.fetched_at} is not usable` : `it is ${Math.floor(age / DAY)} days old (limit ${MAX_STALE_MS / DAY})`;
        throw new ObservationError('ADVISORY_UNAVAILABLE', `${source} advisories could not be refreshed (${reason}) and the cached copy is too old to use: ${why}`);
      }
      throw new ObservationError('ADVISORY_UNAVAILABLE', `${source} advisories are unavailable and nothing is cached: ${reason}`);
    }
    const fetched_at = now.toISOString();
    await this.write(file, { key, fetched_at, value });
    return this.record({ value, fetched_at, stale: false }, source);
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
