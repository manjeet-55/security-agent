import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../src/checks/errors.js';
import type { Advisories } from '../../src/advisories/types.js';
import { EvidenceStore } from '../../src/evidence/store.js';
import { decodeSnapshot, type HostSnapshot } from '../../src/host/snapshot.js';
import { validateProject } from '../../src/project/schema.js';
import { verifyClaim } from '../../src/verify/claim.js';
import { createAdvisories } from '../../src/advisories/index.js';
import { fixtureAdvisories, fixtureFetch, staleAdvisories } from '../helpers/advisories.js';
import { fixtureEnvelope, fixtureSnapshot, readerFor, sectionOf, withSection, withSourceVersion, withVendorOpenssh } from '../helpers/snapshots.js';
import { tempDir } from '../helpers/tmp.js';

const host = validateProject({ version: 1, name: 't', hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }] }).hosts[0]!;

async function verify(snapshot: HostSnapshot | undefined, cve: string, opts: { pkg?: string; kev?: string[]; advisories?: Advisories } = {}) {
  const dir = await tempDir();
  return verifyClaim(
    {
      host,
      snapshots: readerFor(snapshot),
      advisories: opts.advisories ?? fixtureAdvisories(await tempDir(), opts.kev ?? []),
      evidence: new EvidenceStore(dir, 'test'),
      now: () => new Date('2026-10-28T15:00:00Z'),
    },
    { cve, ...(opts.pkg ? { package: opts.pkg } : {}) },
  );
}

describe('verifyClaim on Ubuntu', () => {
  it('fixed_in_installed: CVE-2024-6387 on patched noble openssh', async () => {
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387');
    expect(r).toMatchObject({ verdict: 'fixed_in_installed', source_url: 'https://ubuntu.com/security/CVE-2024-6387', kev: false });
    expect(r.packages).toEqual([
      { package: 'openssh', installed: '1:9.6p1-3ubuntu13.20', distro_status: 'released', fixed: '1:9.6p1-3ubuntu13.3', verdict: 'fixed_in_installed', note: 'installed 1:9.6p1-3ubuntu13.20 >= fixed 1:9.6p1-3ubuntu13.3' },
    ]);
    expect(r.evidence_id).toMatch(/^ev_/);
  });

  it('vulnerable: same CVE with an older openssh', async () => {
    const old = decodeSnapshot(withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13'));
    expect((await verify(old, 'CVE-2024-6387')).verdict).toBe('vulnerable');
  });

  it('not_affected: Ubuntu marks noble not-affected', async () => {
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2021-41617');
    expect(r.verdict).toBe('not_affected');
    expect(r.packages[0]?.distro_status).toBe('not-affected');
  });

  it('no_fix_available: Ubuntu ignores CVE-2016-20012 on jammy', async () => {
    const r = await verify(fixtureSnapshot('ubuntu-22-04'), 'CVE-2016-20012');
    expect(r.verdict).toBe('no_fix_available');
    expect(r.packages[0]).toMatchObject({ package: 'openssh', distro_status: 'ignored' });
  });

  it('unverifiable (not not_affected) when no tracked package is installed', async () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const withoutSsh = sectionOf(env, 'packages')
      .split('\n')
      .filter((l) => l.split('\t')[3] !== 'openssh')
      .join('\n');
    const r = await verify(decodeSnapshot(withSection(env, 'packages', withoutSsh)), 'CVE-2024-6387');
    expect(r.verdict).toBe('unverifiable');
    expect(r.reason).toContain('no dpkg package built from openssh, openssh-ssh1 is installed; if the service runs from a container, snap or source build, verify it there');
  });

  it('maps a binary package name to its source', async () => {
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387', { pkg: 'openssh-server' });
    expect(r.packages.map((p) => p.package)).toEqual(['openssh']);
  });

  it('flags CISA KEV listing', async () => {
    expect((await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387', { kev: ['CVE-2024-6387'] })).kev).toBe(true);
  });
});

function mixedOpenssh(): HostSnapshot {
  const env = fixtureEnvelope('ubuntu-24-04');
  const lines = sectionOf(env, 'packages')
    .split('\n')
    .map((l) => (l.split('\t')[1] === 'openssh-server' ? l.replace(/1:9\.6p1-3ubuntu13\.20/g, '1:9.6p1-3ubuntu13') : l));
  return decodeSnapshot(withSection(env, 'packages', lines.join('\n')));
}

describe('verifyClaim fails closed', () => {
  it('unverifiable when the package filter matches nothing the advisory tracks', async () => {
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387', { pkg: 'not-a-real-package' });
    expect(r.verdict).toBe('unverifiable');
    expect(r.reason).toContain('does not track package "not-a-real-package"');
    expect(r.reason).toContain('openssh');
  });

  it('judges the lowest installed binary version of a source', async () => {
    const r = await verify(mixedOpenssh(), 'CVE-2024-6387');
    expect(r.verdict).toBe('vulnerable');
    expect(r.packages[0]?.installed).toBe('1:9.6p1-3ubuntu13');
  });

  it('unverifiable when Ubuntu has no status for the host codename', async () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const osr = sectionOf(env, 'os_release').replace('VERSION_CODENAME=noble', 'VERSION_CODENAME=oracular').replace('VERSION_ID="24.04"', 'VERSION_ID="24.10"');
    const r = await verify(decodeSnapshot(withSection(env, 'os_release', osr)), 'CVE-2024-6387');
    expect(r.verdict).toBe('unverifiable');
  });

  it('unverifiable when the Ubuntu record tracks no packages', async () => {
    const advisories = fixtureAdvisories(await tempDir());
    advisories.ubuntu = { cve: async (id: string) => ({ id, packages: [] }) } as unknown as Advisories['ubuntu'];
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387', { advisories });
    expect(r.verdict).toBe('unverifiable');
    expect(r.reason).toBe("Ubuntu's record for CVE-2024-6387 lists no packages.");
  });

  it('kev is null when CISA KEV is unavailable', async () => {
    const advisories = fixtureAdvisories(await tempDir());
    advisories.kev = {
      catalog: async () => {
        throw new ObservationError('ADVISORY_UNAVAILABLE', 'offline');
      },
    };
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387', { advisories });
    expect(r.kev).toBeNull();
    expect(r.reason).toContain('CISA KEV was unavailable');
  });
});

describe('verifyClaim on Debian and edge cases', () => {
  it('fixed_in_installed: CVE-2024-6387 on Debian 12 via the OSV Debian record', async () => {
    const r = await verify(fixtureSnapshot('debian-12'), 'CVE-2024-6387');
    expect(r).toMatchObject({ verdict: 'fixed_in_installed', source_url: 'https://security-tracker.debian.org/tracker/CVE-2024-6387' });
    expect(r.packages[0]).toMatchObject({ package: 'openssh', fixed: '1:9.2p1-2+deb12u3' });
  });

  it('unverifiable without an advisory record or without a snapshot', async () => {
    expect((await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-1999-0001')).verdict).toBe('unverifiable');
    const none = await verify(undefined, 'CVE-2024-6387');
    expect(none.verdict).toBe('unverifiable');
    expect(none.reason).toContain('No collector snapshot');
  });

  it('unverifiable when the Debian record lists no packages', async () => {
    const advisories = fixtureAdvisories(await tempDir());
    advisories.osv = { ...advisories.osv, vuln: async (id: string) => ({ id, affected: [] }) } as unknown as Advisories['osv'];
    const r = await verify(fixtureSnapshot('debian-12'), 'CVE-2024-6387', { advisories });
    expect(r.verdict).toBe('unverifiable');
    expect(r.reason).toBe('The Debian record for CVE-2024-6387 lists no packages.');
  });

  it('rejects a malformed CVE id', async () => {
    await expect(verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-24-1')).rejects.toThrow(/Not a CVE id/);
  });
});

/** Replaces every openssh-source binary's version and its apt origin (a vendor repository carrying the same codename). */
function vendorOpenssh(version = '1:9.7p1-1~vendor1', url = 'https://packages.vendor.example/apt'): HostSnapshot {
  return decodeSnapshot(withVendorOpenssh(fixtureEnvelope('ubuntu-24-04'), url, version));
}

describe('verifyClaim v2 fail-closed', () => {
  it('a held vulnerable openssh is still judged vulnerable', async () => {
    const env = withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13');
    const held = sectionOf(env, 'packages').replace(/^ii (\t(openssh-server|openssh-client|openssh-sftp-server)\t)/gm, 'hi $1');
    expect((await verify(decodeSnapshot(withSection(env, 'packages', held)), 'CVE-2024-6387')).verdict).toBe('vulnerable');
  });

  it('vendor-origin openssh above the fixed version is unverifiable, naming the repository', async () => {
    const r = await verify(vendorOpenssh(), 'CVE-2024-6387');
    expect(r.verdict).toBe('unverifiable');
    expect(r.packages[0]).toMatchObject({ verdict: 'unverifiable' });
    expect(r.packages[0]?.note).toContain('packages.vendor.example');
  });

  it.each([
    'https://packagecloud.io/acme/openssh/ubuntu',
    'https://dl.cloudsmith.io/public/acme/openssh/deb/ubuntu',
    'https://dlm.mariadb.com/repo/mariadb-server/11.4/repo/ubuntu',
    'https://repo.zabbix.com/zabbix/7.0/ubuntu',
    'https://ppa1.rabbitmq.com/rabbitmq/rabbitmq-erlang/deb/ubuntu',
    'https://evil.example/ubuntu',
  ])('a vendor build served from %s (path ends /ubuntu) is origin unknown, so unverifiable', async (url) => {
    for (const cve of ['CVE-2024-6387', 'CVE-2021-41617']) {
      const r = await verify(vendorOpenssh('1:9.7p1-1~vendor1', url), cve);
      expect(r.verdict).toBe('unverifiable');
      expect(r.packages[0]?.note).toContain('origin is unknown');
      expect(r.packages[0]?.note).toContain(new URL(url).hostname);
    }
  });

  it('vendor-origin openssh below the fixed version stays vulnerable', async () => {
    expect((await verify(vendorOpenssh('1:9.0p1-1~vendor1'), 'CVE-2024-6387')).verdict).toBe('vulnerable');
  });

  it('Ubuntu DNE on a vendor-origin package does not give not_affected', async () => {
    const r = await verify(vendorOpenssh(), 'CVE-2021-41617');
    expect(r.verdict).toBe('unverifiable');
  });

  it('empty apt lists downgrade a safe verdict', async () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const policy = sectionOf(env, 'apt_policy').replace(/^ {8}\d+ http\S*.*$/gm, '');
    const r = await verify(decodeSnapshot(withSection(env, 'apt_policy', policy)), 'CVE-2024-6387');
    expect(r.verdict).toBe('unverifiable');
    expect(r.packages[0]?.note).toContain('apt package lists are empty');
  });

  it('a failed packages section is unverifiable with evidence, not not_affected', async () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const r = await verify(decodeSnapshot(withSection(env, 'packages', 'dpkg-query: error', 1)), 'CVE-2024-6387');
    expect(r.verdict).toBe('unverifiable');
    expect(r.reason).toContain('no usable installed-package list');
    expect(r.evidence_id).toMatch(/^ev_/);
  });

  it('an advisory outage is unverifiable with the error in the reason', async () => {
    const advisories = fixtureAdvisories(await tempDir());
    advisories.ubuntu = {
      cve: async () => {
        throw new ObservationError('ADVISORY_UNAVAILABLE', 'ubuntu.com is down');
      },
    } as unknown as Advisories['ubuntu'];
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387', { advisories });
    expect(r.verdict).toBe('unverifiable');
    expect(r.reason).toContain('ubuntu.com is down');
    expect(r.evidence_id).toMatch(/^ev_/);
  });

  it('a non-observation error from KEV is not swallowed', async () => {
    const advisories = fixtureAdvisories(await tempDir());
    advisories.kev = {
      catalog: async () => {
        throw new TypeError('bug');
      },
    };
    await expect(verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387', { advisories })).rejects.toThrow('bug');
  });

  it('a snapshot older than 7 days makes safe verdicts unverifiable but keeps vulnerable', async () => {
    const stale = { ...fixtureEnvelope('ubuntu-24-04'), collected_at: '2026-10-10T00:00:00Z' };
    const r = await verify(decodeSnapshot(stale), 'CVE-2024-6387');
    expect(r.verdict).toBe('unverifiable');
    expect(r.reason).toContain('days old');
    const old = decodeSnapshot({ ...withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13'), collected_at: '2026-10-10T00:00:00Z' });
    expect((await verify(old, 'CVE-2024-6387')).verdict).toBe('vulnerable');
  });

  it('a future-dated snapshot makes safe verdicts unverifiable', async () => {
    const future = { ...fixtureEnvelope('ubuntu-24-04'), collected_at: '2026-11-30T00:00:00Z' };
    const r = await verify(decodeSnapshot(future), 'CVE-2024-6387');
    expect(r.verdict).toBe('unverifiable');
    expect(r.reason).toContain('in the future');
  });

  it('Debian: no fixed version for the release is no_fix_available', async () => {
    const advisories = fixtureAdvisories(await tempDir());
    const real = advisories.osv;
    advisories.osv = {
      ...real,
      vuln: async (id: string) => {
        const v = (await real.vuln(id)) as unknown as { affected: Array<{ package: { ecosystem: string }; ranges: Array<{ events: Array<Record<string, string>> }> }> };
        for (const a of v.affected) if (a.package.ecosystem === 'Debian:12') a.ranges = [{ events: [{ introduced: '0' }] }];
        return v;
      },
    } as unknown as Advisories['osv'];
    const r = await verify(fixtureSnapshot('debian-12'), 'CVE-2024-6387', { advisories });
    expect(r.verdict).toBe('no_fix_available');
    expect(r.packages[0]?.distro_status).toBe('open');
  });

  it('multi-package precedence: vulnerable beats fixed_in_installed', async () => {
    const advisories = fixtureAdvisories(await tempDir());
    const real = advisories.osv;
    advisories.osv = {
      ...real,
      vuln: async (id: string) => {
        const v = (await real.vuln(id)) as unknown as { affected: Array<{ package: { name: string; ecosystem: string }; ranges: unknown }> };
        const extra = v.affected.filter((a) => a.package.ecosystem === 'Debian:12').map((a) => ({
          ...a,
          package: { ...a.package, name: 'openssl' },
          ranges: [{ type: 'ECOSYSTEM', events: [{ introduced: '0' }, { fixed: '99:1.0' }] }],
        }));
        return { ...v, affected: [...v.affected, ...extra] };
      },
    } as unknown as Advisories['osv'];
    const r = await verify(fixtureSnapshot('debian-12'), 'CVE-2024-6387', { advisories });
    expect(r.packages.map((p) => p.verdict).sort()).toEqual(['fixed_in_installed', 'vulnerable']);
    expect(r.verdict).toBe('vulnerable');
  });
});

describe('verifyClaim advisory freshness', () => {
  it('reports as_of and stale=false for fresh data', async () => {
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387');
    expect(r.stale).toBe(false);
    expect(r.as_of).toMatch(/^\d{4}-\d{2}-\d{2}T/);
  });

  it('stale advisory data turns fixed_in_installed and not_affected into unverifiable', async () => {
    for (const cve of ['CVE-2024-6387', 'CVE-2021-41617']) {
      const advisories = await staleAdvisories(await tempDir(), (a) => a.ubuntu.cve(cve));
      const r = await verify(fixtureSnapshot('ubuntu-24-04'), cve, { advisories });
      expect(r).toMatchObject({ verdict: 'unverifiable', stale: true, as_of: '2026-10-20T00:00:00.000Z' });
      expect(r.reason).toContain('advisory data is stale (as of 2026-10-20)');
      expect(r.packages[0]?.note).toContain('advisory data is stale (as of 2026-10-20)');
    }
  });

  it('stale data does not hide a vulnerable verdict', async () => {
    const old = decodeSnapshot(withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13'));
    const advisories = await staleAdvisories(await tempDir(), (a) => a.ubuntu.cve('CVE-2024-6387'));
    const r = await verify(old, 'CVE-2024-6387', { advisories });
    expect(r).toMatchObject({ verdict: 'vulnerable', stale: true });
  });

  it('counts a stale KEV catalog in the reported as_of and stale flag, and blocks dismissal', async () => {
    const dir = await tempDir();
    const now = new Date('2026-10-28T15:00:00Z');
    await createAdvisories({ cacheDir: dir, fetchJson: fixtureFetch(), now: () => new Date(now.getTime() - 20 * 86_400_000) }).kev.catalog();
    await createAdvisories({ cacheDir: dir, fetchJson: fixtureFetch(), now: () => now }).ubuntu.cve('CVE-2024-6387');
    const offline = async (): Promise<never> => {
      throw new Error('offline');
    };
    const advisories = createAdvisories({ cacheDir: dir, fetchJson: offline, now: () => now });
    const r = await verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-2024-6387', { advisories });
    expect(r).toMatchObject({ verdict: 'unverifiable', stale: true, as_of: '2026-10-08T15:00:00.000Z', kev: false });
    expect(r.reason).toContain('advisory data is stale (as of 2026-10-08)');
  });
});
