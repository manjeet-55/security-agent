import { AdvisoryCache } from './cache.js';
import { createFetchJson, type FetchJson } from './fetch.js';
import { KevClient } from './kev.js';
import { OsvClient } from './osv.js';
import type { Advisories } from './types.js';
import { UbuntuCveClient } from './ubuntu.js';

export type { Advisories } from './types.js';

export function createAdvisories(opts: { cacheDir?: string; fetchJson?: FetchJson; now?: () => Date } = {}): Advisories {
  const cache = new AdvisoryCache(opts.cacheDir, opts.now);
  const fetchJson = opts.fetchJson ?? createFetchJson();
  return {
    osv: new OsvClient(fetchJson, cache),
    ubuntu: new UbuntuCveClient(fetchJson, cache),
    kev: new KevClient(fetchJson, cache, opts.now),
    freshness: () => cache.freshness(),
  };
}
