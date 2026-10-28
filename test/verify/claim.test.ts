import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../src/checks/errors.js';
import type { Advisories } from '../../src/advisories/types.js';
import { EvidenceStore } from '../../src/evidence/store.js';
import { decodeSnapshot, type HostSnapshot } from '../../src/host/snapshot.js';
import { validateProject } from '../../src/project/schema.js';
import { verifyClaim } from '../../src/verify/claim.js';
import { fixtureAdvisories } from '../helpers/advisories.js';
import { fixtureEnvelope, fixtureSnapshot, readerFor, sectionOf, withSection, withSourceVersion } from '../helpers/snapshots.js';
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
function vendorOpenssh(version = '1:9.7p1-1~vendor1'): HostSnapshot {
  const env = withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', version);
  let policy = sectionOf(env, 'apt_policy');
  for (const bin of ['openssh-client', 'openssh-server', 'openssh-sftp-server']) {
    policy += `\n${bin}:\n  Installed: ${version}\n  Candidate: ${version}\n  Version table:\n *** ${version} 500\n        500 https://packages.vendor.example/apt noble/main amd64 Packages\n        100 /var/lib/dpkg/status\n`;
  }
  return decodeSnapshot(withSection(env, 'apt_policy', policy));
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
