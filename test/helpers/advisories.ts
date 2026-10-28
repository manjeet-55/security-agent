import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import type { FetchJson } from '../../src/advisories/fetch.js';
import { createAdvisories } from '../../src/advisories/index.js';
import type { Advisories } from '../../src/advisories/types.js';

const DIR = path.join(import.meta.dirname, '..', 'fixtures', 'advisories');
const CODENAMES: Record<string, string> = { 'Ubuntu:24.04:LTS': 'noble', 'Ubuntu:22.04:LTS': 'jammy', 'Debian:12': 'bookworm' };

function load(rel: string): unknown {
  return JSON.parse(readFileSync(path.join(DIR, rel), 'utf8'));
}

function queryFixture(ecosystem: string, name: string, version: string): string | undefined {
  const rel = `osv/query-${name}-${CODENAMES[ecosystem] ?? 'x'}-${version.replace(/:/g, '.')}.json`;
  return existsSync(path.join(DIR, rel)) ? rel : undefined;
}

/** Serves recorded advisory responses; anything not recorded is a 404 (or an empty OSV result). Records every request. */
export function fixtureFetch(extraKev: string[] = []): FetchJson & { calls: string[] } {
  const calls: string[] = [];
  const fn = async (url: string, init: { method?: 'GET' | 'POST'; body?: unknown } = {}) => {
    calls.push(`${init.method ?? 'GET'} ${url}`);
    const u = new URL(url);
    if (u.hostname === 'ubuntu.com') {
      const id = /\/cves\/(CVE-[\d-]+)\.json$/.exec(u.pathname)?.[1];
      const rel = `ubuntu/${id}.json`;
      return id && existsSync(path.join(DIR, rel)) ? { status: 200, json: load(rel) } : { status: 404, json: null };
    }
    if (u.hostname === 'www.cisa.gov') {
      const kev = load('kev/known_exploited_vulnerabilities.sample.json') as { vulnerabilities: Array<{ cveID: string }> };
      return { status: 200, json: { ...kev, vulnerabilities: [...kev.vulnerabilities, ...extraKev.map((cveID) => ({ cveID }))] } };
    }
    if (u.pathname.startsWith('/v1/vulns/')) {
      const rel = `osv/${decodeURIComponent(u.pathname.slice('/v1/vulns/'.length))}.json`;
      return existsSync(path.join(DIR, rel)) ? { status: 200, json: load(rel) } : { status: 404, json: null };
    }
    if (u.pathname === '/v1/query') {
      const b = init.body as { package: { name: string; ecosystem: string }; version: string };
      const rel = queryFixture(b.package.ecosystem, b.package.name, b.version);
      return { status: 200, json: rel ? load(rel) : {} };
    }
    if (u.pathname === '/v1/querybatch') {
      const b = init.body as { queries: Array<{ package: { name: string; ecosystem: string }; version: string }> };
      return {
        status: 200,
        json: { results: b.queries.map((q) => (queryFixture(q.package.ecosystem, q.package.name, q.version) ? { vulns: [{ id: 'x' }] } : {})) },
      };
    }
    return { status: 404, json: null };
  };
  return Object.assign(fn, { calls });
}

export function fixtureAdvisories(cacheDir: string, extraKev: string[] = []): Advisories {
  return createAdvisories({ cacheDir, fetchJson: fixtureFetch(extraKev) });
}

export const STALE_FETCHED_AT = '2026-10-20T00:00:00.000Z';

/** Advisories whose cache was filled on 2026-10-20 and whose sources are unreachable now (10 days later): every answer is a stale copy. */
export async function staleAdvisories(cacheDir: string, warm: (a: Advisories) => Promise<unknown>): Promise<Advisories> {
  const t0 = new Date(STALE_FETCHED_AT);
  await warm(createAdvisories({ cacheDir, fetchJson: fixtureFetch(), now: () => t0 }));
  const offline: FetchJson = async () => {
    throw new Error('offline');
  };
  return createAdvisories({ cacheDir, fetchJson: offline, now: () => new Date(t0.getTime() + 10 * 86_400_000) });
}
