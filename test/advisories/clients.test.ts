import { describe, expect, it } from 'vitest';
import { AdvisoryCache } from '../../src/advisories/cache.js';
import { KevClient } from '../../src/advisories/kev.js';
import { cveIdsOf, fixedVersionFor, OsvClient, ubuntuPriority } from '../../src/advisories/osv.js';
import { UbuntuCveClient } from '../../src/advisories/ubuntu.js';
import { ObservationError } from '../../src/checks/errors.js';
import type { FetchJson } from '../../src/advisories/fetch.js';
import { fixtureFetch } from '../helpers/advisories.js';
import { tempDir } from '../helpers/tmp.js';

const NOBLE = 'Ubuntu:24.04:LTS';

describe('OsvClient', () => {
  it('finds affected source packages, then their vulns with fixed versions and CVE ids', async () => {
    const fetchJson = fixtureFetch();
    const osv = new OsvClient(fetchJson, new AdvisoryCache(await tempDir()));
    const affected = await osv.affected(NOBLE, [
      { name: 'openssh', version: '1:9.6p1-3ubuntu13' },
      { name: 'bash', version: '5.2.21-2ubuntu4' },
    ]);
    expect([...affected]).toEqual(['openssh']);
    const vulns = await osv.vulnsFor(NOBLE, { name: 'openssh', version: '1:9.6p1-3ubuntu13' });
    const v = vulns.find((x) => x.id === 'UBUNTU-CVE-2024-6387');
    expect(v).toBeDefined();
    if (!v) return;
    expect(fixedVersionFor(v, NOBLE, 'openssh')).toBe('1:9.6p1-3ubuntu13.3');
    expect(cveIdsOf(v)).toEqual(['CVE-2024-6387']);
    expect(ubuntuPriority(v)).toBe('high');
  });

  it('caches responses', async () => {
    const fetchJson = fixtureFetch();
    const osv = new OsvClient(fetchJson, new AdvisoryCache(await tempDir()));
    await osv.vuln('DEBIAN-CVE-2024-6387');
    await osv.vuln('DEBIAN-CVE-2024-6387');
    expect(fetchJson.calls).toHaveLength(1);
  });

  it('returns null for unknown vulns and reads Debian fixed versions', async () => {
    const osv = new OsvClient(fixtureFetch(), new AdvisoryCache(await tempDir()));
    expect(await osv.vuln('DEBIAN-CVE-1999-0001')).toBeNull();
    const d = await osv.vuln('DEBIAN-CVE-2024-6387');
    expect(d && fixedVersionFor(d, 'Debian:12', 'openssh')).toBe('1:9.2p1-2+deb12u3');
  });
});

describe('UbuntuCveClient', () => {
  it('returns per-release statuses, null for unknown CVEs, and rejects non-CVE ids', async () => {
    const ubuntu = new UbuntuCveClient(fixtureFetch(), new AdvisoryCache(await tempDir()));
    const cve = await ubuntu.cve('CVE-2021-41617');
    const noble = cve?.packages.find((p) => p.name === 'openssh')?.statuses.find((s) => s.release_codename === 'noble');
    expect(noble?.status).toBe('not-affected');
    expect(await ubuntu.cve('CVE-1999-0001')).toBeNull();
    await expect(ubuntu.cve('not-a-cve')).rejects.toThrow(/Not a CVE id/);
  });
});

describe('KevClient', () => {
  it('loads the catalog once', async () => {
    const fetchJson = fixtureFetch(['CVE-2024-6387']);
    const kev = new KevClient(fetchJson, new AdvisoryCache(await tempDir()));
    expect((await kev.catalog()).has('CVE-2024-6387')).toBe(true);
    expect((await kev.catalog()).has('CVE-2026-48356')).toBe(true);
    expect(fetchJson.calls).toHaveLength(1);
  });

  it('refreshes the catalog after the cache entry expires and keeps reporting freshness', async () => {
    let now = new Date('2026-10-28T00:00:00Z');
    const fetchJson = fixtureFetch();
    const cache = new AdvisoryCache(await tempDir(), () => now);
    const kev = new KevClient(fetchJson, cache, () => now);
    await kev.catalog();
    cache.freshness();
    now = new Date(now.getTime() + 3_600_000);
    await kev.catalog();
    expect(fetchJson.calls).toHaveLength(1);
    expect(cache.freshness()).toEqual({ as_of: '2026-10-28T00:00:00.000Z', stale: false });
    now = new Date(now.getTime() + 86_400_000);
    await kev.catalog();
    expect(fetchJson.calls).toHaveLength(2);
  });

  it('de-duplicates concurrent first loads', async () => {
    const fetchJson = fixtureFetch();
    const kev = new KevClient(fetchJson, new AdvisoryCache(await tempDir()));
    await Promise.all([kev.catalog(), kev.catalog(), kev.catalog()]);
    expect(fetchJson.calls).toHaveLength(1);
  });
});

describe('missing advisory responses are unavailable, not clean', () => {
  const notFound: FetchJson = async () => ({ status: 404, json: null });
  const unavailable = expect.objectContaining({ name: 'ObservationError', code: 'ADVISORY_UNAVAILABLE' });

  it('vulnsFor stops after 50 pages instead of paginating forever', async () => {
    let calls = 0;
    const endless: FetchJson = async () => {
      calls += 1;
      return { status: 200, json: { vulns: [], next_page_token: `t${calls}` } };
    };
    const osv = new OsvClient(endless, new AdvisoryCache(await tempDir()));
    await expect(osv.vulnsFor(NOBLE, { name: 'openssh', version: '1' })).rejects.toEqual(unavailable);
    expect(calls).toBe(50);
  });

  it('affected rejects on a 404 querybatch', async () => {
    const osv = new OsvClient(notFound, new AdvisoryCache(await tempDir()));
    const p = osv.affected(NOBLE, [{ name: 'openssh', version: '1' }]);
    await expect(p).rejects.toBeInstanceOf(ObservationError);
    await expect(p).rejects.toEqual(unavailable);
  });

  it('vulnsFor rejects on a 404 query', async () => {
    const osv = new OsvClient(notFound, new AdvisoryCache(await tempDir()));
    await expect(osv.vulnsFor(NOBLE, { name: 'openssh', version: '1' })).rejects.toEqual(unavailable);
  });

  it('KevClient.catalog rejects on 404 and retries on the next call', async () => {
    let up = false;
    const fetchJson: FetchJson = async () =>
      up ? { status: 200, json: { vulnerabilities: [{ cveID: 'CVE-2024-6387' }] } } : { status: 404, json: null };
    const kev = new KevClient(fetchJson, new AdvisoryCache(await tempDir()));
    await expect(kev.catalog()).rejects.toEqual(unavailable);
    up = true;
    expect((await kev.catalog()).has('CVE-2024-6387')).toBe(true);
  });

  it('follows next_page_token across exactly 2 POSTs', async () => {
    const bodies: Array<Record<string, unknown>> = [];
    const fetchJson: FetchJson = async (_url, init) => {
      const body = init?.body as Record<string, unknown>;
      bodies.push(body);
      return body.page_token === 't'
        ? { status: 200, json: { vulns: [{ id: 'B' }] } }
        : { status: 200, json: { vulns: [{ id: 'A' }], next_page_token: 't' } };
    };
    const osv = new OsvClient(fetchJson, new AdvisoryCache(await tempDir()));
    const vulns = await osv.vulnsFor(NOBLE, { name: 'openssh', version: '1' });
    expect(vulns.map((v) => v.id)).toEqual(['A', 'B']);
    expect(bodies).toHaveLength(2);
  });

  it('chunks 1,001 queries into 2 querybatch POSTs', async () => {
    const sizes: number[] = [];
    const fetchJson: FetchJson = async (_url, init) => {
      const n = (init?.body as { queries: unknown[] }).queries.length;
      sizes.push(n);
      return { status: 200, json: { results: Array.from({ length: n }, () => ({})) } };
    };
    const osv = new OsvClient(fetchJson, new AdvisoryCache(await tempDir()));
    const queries = Array.from({ length: 1001 }, (_, i) => ({ name: `p${i}`, version: '1' }));
    expect((await osv.affected(NOBLE, queries)).size).toBe(0);
    expect(sizes).toEqual([1000, 1]);
  });

  it('vuln and ubuntu.cve still return null on 404', async () => {
    const osv = new OsvClient(notFound, new AdvisoryCache(await tempDir()));
    expect(await osv.vuln('X')).toBeNull();
    const ubuntu = new UbuntuCveClient(notFound, new AdvisoryCache(await tempDir()));
    expect(await ubuntu.cve('CVE-1999-0001')).toBeNull();
  });
});
