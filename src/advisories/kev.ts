import { TTL, type AdvisoryCache, type Cached } from './cache.js';
import type { FetchJson } from './fetch.js';
import type { KevSource } from './types.js';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

/** After a stale answer (source unreachable) the refresh is retried at most this often. */
const STALE_RETRY_MS = 10 * 60_000;

interface Loaded {
  result: Cached<Set<string>>;
  expires: number;
}

export class KevClient implements KevSource {
  private loaded: Promise<Loaded> | undefined;

  constructor(
    private readonly fetchJson: FetchJson,
    private readonly cache: AdvisoryCache,
    private readonly now: () => Date = () => new Date(),
  ) {}

  /** The catalog is memoised in memory only until its cache entry expires (`fetched_at` + TTL), so a long-lived process refreshes it. */
  async catalog(): Promise<Set<string>> {
    const pending = this.loaded;
    if (pending !== undefined) {
      const current = await pending;
      if (this.now().getTime() < current.expires) {
        this.cache.record(current.result);
        return current.result.value;
      }
      if (this.loaded === pending) this.loaded = undefined;
    }
    return (await (this.loaded ??= this.load())).result.value;
  }

  private load(): Promise<Loaded> {
    const p: Promise<Loaded> = this.cache
      .getOrFetch('kev', KEV_URL, TTL.kev, async () => {
        const res = await this.fetchJson(KEV_URL);
        if (res.status === 404) throw new Error('KEV catalog returned 404');
        const json = res.json as { vulnerabilities?: Array<{ cveID?: unknown }> } | null;
        if (json === null || typeof json !== 'object' || !Array.isArray(json.vulnerabilities)) {
          throw new Error('KEV catalog is malformed: no vulnerabilities array');
        }
        return json.vulnerabilities.map((v) => v.cveID).filter((id): id is string => typeof id === 'string');
      })
      .then(
        (c) => {
          const expires = c.stale ? this.now().getTime() + STALE_RETRY_MS : Date.parse(c.fetched_at) + TTL.kev;
          return { result: { ...c, value: new Set(c.value) }, expires };
        },
        (e: unknown) => {
          if (this.loaded === p) this.loaded = undefined;
          throw e;
        },
      );
    return p;
  }
}
