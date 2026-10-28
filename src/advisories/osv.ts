import { TTL, type AdvisoryCache } from './cache.js';
import type { FetchJson, JsonResponse } from './fetch.js';
import type { OsvSource, OsvVuln, PackageQuery } from './types.js';

const OSV = 'https://api.osv.dev/v1';
const BATCH = 1000;
const MAX_PAGES = 50;

/** A 404 or non-object body is a missing answer, never an empty one: throw so the cache serves stale or reports unavailable. */
function requireBody<T>(res: JsonResponse, what: string): T {
  if (res.status === 404) throw new Error(`${what} returned 404`);
  if (res.json === null || typeof res.json !== 'object' || Array.isArray(res.json)) throw new Error(`${what} returned no JSON object`);
  return res.json as T;
}

export class OsvClient implements OsvSource {
  constructor(
    private readonly fetchJson: FetchJson,
    private readonly cache: AdvisoryCache,
  ) {}

  async affected(ecosystem: string, queries: readonly PackageQuery[]): Promise<Set<string>> {
    const hits = new Set<string>();
    for (let i = 0; i < queries.length; i += BATCH) {
      const chunk = queries.slice(i, i + BATCH);
      const key = `batch ${ecosystem} ${chunk
        .map((q) => `${q.name}@${q.version}`)
        .sort()
        .join(',')}`;
      const { value } = await this.cache.getOrFetch('osv', key, TTL.osv, async () => {
        const res = await this.fetchJson(`${OSV}/querybatch`, {
          method: 'POST',
          body: { queries: chunk.map((q) => ({ package: { name: q.name, ecosystem }, version: q.version })) },
        });
        const results = requireBody<{ results?: Array<{ vulns?: unknown[] }> }>(res, 'OSV querybatch').results;
        if (!Array.isArray(results) || results.length !== chunk.length) throw new Error('OSV querybatch returned a malformed results array');
        return chunk.filter((_, idx) => (results[idx]?.vulns?.length ?? 0) > 0).map((q) => q.name);
      });
      for (const name of value) hits.add(name);
    }
    return hits;
  }

  async vulnsFor(ecosystem: string, query: PackageQuery): Promise<OsvVuln[]> {
    const { value } = await this.cache.getOrFetch('osv', `query ${ecosystem} ${query.name}@${query.version}`, TTL.osv, async () => {
      const vulns: OsvVuln[] = [];
      let pageToken: string | undefined;
      let pages = 0;
      do {
        if (pages >= MAX_PAGES) throw new Error(`OSV query for ${query.name} has more than ${MAX_PAGES} pages`);
        pages += 1;
        const res = await this.fetchJson(`${OSV}/query`, {
          method: 'POST',
          body: { package: { name: query.name, ecosystem }, version: query.version, ...(pageToken ? { page_token: pageToken } : {}) },
        });
        const body = requireBody<{ vulns?: OsvVuln[]; next_page_token?: string }>(res, 'OSV query');
        vulns.push(...(body.vulns ?? []));
        pageToken = body.next_page_token;
      } while (pageToken);
      return vulns;
    });
    return value;
  }

  async vuln(id: string): Promise<OsvVuln | null> {
    const { value } = await this.cache.getOrFetch('osv', `vuln ${id}`, TTL.osv, async () => {
      return (await this.fetchJson(`${OSV}/vulns/${encodeURIComponent(id)}`)).json as OsvVuln | null;
    });
    return value;
  }
}

/** The first `fixed` event for this ecosystem and source package, if the advisory has one. */
export function fixedVersionFor(v: OsvVuln, ecosystem: string, name: string): string | undefined {
  for (const a of v.affected ?? []) {
    if (a.package.ecosystem !== ecosystem || a.package.name !== name) continue;
    for (const r of a.ranges ?? []) {
      for (const e of r.events) if (e.fixed) return e.fixed;
    }
  }
  return undefined;
}

export function cveIdsOf(v: OsvVuln): string[] {
  const fromId = /CVE-\d{4}-\d+/.exec(v.id)?.[0];
  const all = [...(v.upstream ?? []), ...(v.aliases ?? []), ...(fromId ? [fromId] : [])];
  return [...new Set(all.filter((id) => /^CVE-\d{4}-\d+$/.test(id)))];
}

/** Ubuntu's own priority (negligible | low | medium | high | critical) when the record carries one. */
export function ubuntuPriority(v: OsvVuln): string | undefined {
  return v.severity?.find((s) => s.type === 'Ubuntu')?.score;
}
