import { TTL, type AdvisoryCache } from './cache.js';
import type { FetchJson } from './fetch.js';
import type { KevSource } from './types.js';

export const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

export class KevClient implements KevSource {
  private loaded: Promise<Set<string>> | undefined;

  constructor(
    private readonly fetchJson: FetchJson,
    private readonly cache: AdvisoryCache,
  ) {}

  catalog(): Promise<Set<string>> {
    this.loaded ??= this.cache
      .getOrFetch('kev', KEV_URL, TTL.kev, async () => {
        const json = (await this.fetchJson(KEV_URL)).json as { vulnerabilities?: Array<{ cveID?: unknown }> } | null;
        return (json?.vulnerabilities ?? []).map((v) => v.cveID).filter((id): id is string => typeof id === 'string');
      })
      .then((c) => new Set(c.value));
    return this.loaded;
  }
}
