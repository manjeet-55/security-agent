import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../../src/checks/errors.js';
import { distroSources, findFixable, hostPackageCheck, hostPackageParams } from '../../../src/checks/types/host-package.js';
import { decodeSnapshot } from '../../../src/host/snapshot.js';
import { fixtureAdvisories } from '../../helpers/advisories.js';
import { hostSubject, makeCtx } from '../../helpers/ctx.js';
import { fixtureEnvelope, fixtureSnapshot, readerFor, sectionOf, withSection, withSourceVersion } from '../../helpers/snapshots.js';
import { tempDir } from '../../helpers/tmp.js';

const P = (p: Record<string, unknown>) => hostPackageParams.parse(p);

async function run(snapshot: ReturnType<typeof decodeSnapshot>, params: Record<string, unknown>, extraKev: string[] = []) {
  const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(snapshot), advisories: fixtureAdvisories(await tempDir(), extraKev) });
  return hostPackageCheck.run(ctx, hostSubject(ctx), P(params), {} as never);
}

describe('distroSources', () => {
  it('returns one entry per source package at its highest installed version', () => {
    const sources = distroSources(fixtureSnapshot('ubuntu-24-04'), 'noble');
    expect(sources.filter((s) => s.name === 'openssh')).toEqual([{ name: 'openssh', version: '1:9.6p1-3ubuntu13.20' }]);
    expect(new Set(sources.map((s) => s.name)).size).toBe(sources.length);
  });
});

describe('host_package advisories', () => {
  it('passes a fully patched host', async () => {
    const out = await run(fixtureSnapshot('ubuntu-24-04'), { assert: 'advisories' });
    expect(out.outcome).toBe('pass');
    expect(out.observed).toContain('no security fixes pending');
  });

  it('fails an outdated openssh with the fixed versions, at the highest Ubuntu priority', async () => {
    const old = decodeSnapshot(withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13'));
    const out = await run(old, { assert: 'advisories' });
    expect(out).toMatchObject({ outcome: 'fail', severity: 'high' });
    expect(out.observed).toContain('CVE-2024-6387 high fixed in 1:9.6p1-3ubuntu13.3');
  });

  it('escalates to critical when a CVE is on the CISA KEV list', async () => {
    const old = decodeSnapshot(withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13'));
    const out = await run(old, { assert: 'advisories' }, ['CVE-2025-26465']);
    expect(out.severity).toBe('critical');
    expect(out.observed).toContain('KEV');
  });

  it('counts advisories without a released fix but does not fail on them', async () => {
    const out = await run(fixtureSnapshot('ubuntu-22-04'), { assert: 'advisories' });
    expect(out.outcome).toBe('pass');
    expect(out.observed).toContain('1 advisories have no released fix yet');
  });

  it('is unverifiable for non-Debian hosts', async () => {
    const rhel = decodeSnapshot(withSection(fixtureEnvelope('ubuntu-24-04'), 'os_release', 'ID=rhel\nVERSION_ID="9.4"\n'));
    await expect(run(rhel, { assert: 'advisories' })).rejects.toBeInstanceOf(ObservationError);
  });

  it('reports KEV unavailability instead of failing the whole check', async () => {
    const snapshot = fixtureSnapshot('ubuntu-24-04');
    const advisories = fixtureAdvisories(await tempDir());
    advisories.kev = {
      catalog: async () => {
        throw new ObservationError('ADVISORY_UNAVAILABLE', 'offline');
      },
    };
    const sources = distroSources(snapshot, 'noble');
    expect((await findFixable(advisories, 'Ubuntu:24.04:LTS', sources)).kev_available).toBe(false);
  });
});

describe('host_package third_party and reboot', () => {
  const env = fixtureEnvelope('ubuntu-24-04');

  it('passes when every package comes from distro repositories', async () => {
    expect((await run(fixtureSnapshot('ubuntu-24-04'), { assert: 'third_party' })).outcome).toBe('pass');
  });

  it('fails packages from vendor repositories or installed locally', async () => {
    const policy = `${sectionOf(env, 'apt_policy')}\nnginx:\n  Installed: 1.30.6-1~noble\n *** 1.30.6-1~noble 500\n        500 http://nginx.org/packages/ubuntu noble/nginx amd64 Packages\n        100 /var/lib/dpkg/status\n`;
    const packages = sectionOf(env, 'packages').replace(/^ii \tnginx\t[^\n]*$/m, 'ii \tnginx\t1.30.6-1~noble\tnginx\t1.30.6-1~noble');
    const snap = decodeSnapshot(withSection(withSection(env, 'apt_policy', policy), 'packages', packages));
    const out = await run(snap, { assert: 'third_party' });
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('nginx 1.30.6-1~noble (http://nginx.org/packages/ubuntu noble/nginx amd64 Packages)');
  });

  it('is unverifiable when apt lists are empty', async () => {
    const policy = sectionOf(env, 'apt_policy').replace(/^ {8}\d+ http\S*.*$/gm, '');
    const snap = decodeSnapshot(withSection(env, 'apt_policy', policy));
    await expect(run(snap, { assert: 'third_party' })).rejects.toMatchObject({ code: 'APT_LISTS_EMPTY' });
  });

  it('flags a pending reboot', async () => {
    expect((await run(fixtureSnapshot('ubuntu-24-04'), { assert: 'reboot' })).outcome).toBe('pass');
    const snap = decodeSnapshot(withSection(env, 'reboot', 'required\nlinux-image-6.8.0-90-generic\n'));
    expect((await run(snap, { assert: 'reboot' })).observed).toBe('a reboot is pending (packages: linux-image-6.8.0-90-generic)');
  });
});
