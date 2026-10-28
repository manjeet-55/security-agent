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

  it('not_affected when no tracked package is installed', async () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const withoutSsh = sectionOf(env, 'packages')
      .split('\n')
      .filter((l) => l.split('\t')[3] !== 'openssh')
      .join('\n');
    const r = await verify(decodeSnapshot(withSection(env, 'packages', withoutSsh)), 'CVE-2024-6387');
    expect(r.verdict).toBe('not_affected');
    expect(r.reason).toContain('none of the packages Ubuntu tracks for CVE-2024-6387 (openssh, openssh-ssh1) are installed');
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
