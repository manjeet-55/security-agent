import { describe, expect, it } from 'vitest';
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

  it('rejects a malformed CVE id', async () => {
    await expect(verify(fixtureSnapshot('ubuntu-24-04'), 'CVE-24-1')).rejects.toThrow(/Not a CVE id/);
  });
});
