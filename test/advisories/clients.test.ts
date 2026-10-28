import { describe, expect, it } from 'vitest';
import { AdvisoryCache } from '../../src/advisories/cache.js';
import { KevClient } from '../../src/advisories/kev.js';
import { cveIdsOf, fixedVersionFor, OsvClient, ubuntuPriority } from '../../src/advisories/osv.js';
import { UbuntuCveClient } from '../../src/advisories/ubuntu.js';
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
});
