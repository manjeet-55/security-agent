import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../../src/checks/errors.js';
import { distroSources, findFixable, hostPackageCheck, hostPackageParams, skippedSourceCount } from '../../../src/checks/types/host-package.js';
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
  it('returns one entry per source package at its lowest installed version', () => {
    const sources = distroSources(fixtureSnapshot('ubuntu-24-04'), 'noble');
    expect(sources.filter((s) => s.name === 'openssh')).toEqual([{ name: 'openssh', version: '1:9.6p1-3ubuntu13.20' }]);
    expect(new Set(sources.map((s) => s.name)).size).toBe(sources.length);
  });
});

describe('distroSources with mixed binary versions', () => {
  function mixed() {
    const env = fixtureEnvelope('ubuntu-24-04');
    const lines = sectionOf(env, 'packages')
      .split('\n')
      .map((l) => (l.split('\t')[1] === 'openssh-server' ? l.replace(/1:9\.6p1-3ubuntu13\.20/g, '1:9.6p1-3ubuntu13') : l));
    return decodeSnapshot(withSection(env, 'packages', lines.join('\n')));
  }

  it('takes the lowest installed version per source', () => {
    expect(distroSources(mixed(), 'noble').filter((s) => s.name === 'openssh')).toEqual([{ name: 'openssh', version: '1:9.6p1-3ubuntu13' }]);
  });

  it('advisories fail with CVE-2024-6387 on that snapshot', async () => {
    const r = await run(mixed(), { assert: 'advisories' });
    expect(r.outcome).toBe('fail');
    expect(r.observed).toContain('CVE-2024-6387');
  });
});

describe('skippedSourceCount', () => {
  it('is zero when every package is from the distro', () => {
    expect(skippedSourceCount(fixtureSnapshot('ubuntu-24-04'), 'noble')).toBe(0);
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

  it('is unverifiable when no installed package can be attributed to distro repositories', async () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const policy = sectionOf(env, 'apt_policy').replace(/^( {8}\d+ )http\S* \S+/gm, '$1http://vendor.example.com/apt stable/main');
    const snap = decodeSnapshot(withSection(env, 'apt_policy', policy));
    await expect(run(snap, { assert: 'advisories' })).rejects.toMatchObject({ code: 'NO_DISTRO_PACKAGES' });
  });

  it('propagates an unavailable OSV instead of passing', async () => {
    const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(fixtureSnapshot('ubuntu-24-04')), advisories: fixtureAdvisories(await tempDir()) });
    ctx.advisories.osv = {
      ...ctx.advisories.osv,
      affected: async () => {
        throw new ObservationError('ADVISORY_UNAVAILABLE', 'offline');
      },
    };
    await expect(hostPackageCheck.run(ctx, hostSubject(ctx), P({ assert: 'advisories' }), {} as never)).rejects.toMatchObject({
      code: 'ADVISORY_UNAVAILABLE',
    });
  });

  it('says how many non-distro packages were not checked', async () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const policy = `${sectionOf(env, 'apt_policy')}\nnginx:\n  Installed: 1.30.6-1~noble\n *** 1.30.6-1~noble 500\n        500 http://nginx.org/packages/ubuntu noble/nginx amd64 Packages\n        100 /var/lib/dpkg/status\n`;
    const packages = sectionOf(env, 'packages').replace(/^ii \tnginx\t[^\n]*$/m, 'ii \tnginx\t1.30.6-1~noble\tnginx\t1.30.6-1~noble');
    const snap = decodeSnapshot(withSection(withSection(env, 'apt_policy', policy), 'packages', packages));
    const out = await run(snap, { assert: 'advisories' });
    expect(out.outcome).toBe('pass');
    expect(out.observed).toContain('1 non-distro packages not checked (see host-package-third-party)');
  });

  it('tells the reader when CISA KEV was unavailable', async () => {
    const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(fixtureSnapshot('ubuntu-24-04')), advisories: fixtureAdvisories(await tempDir()) });
    ctx.advisories.kev = {
      catalog: async () => {
        throw new ObservationError('ADVISORY_UNAVAILABLE', 'offline');
      },
    };
    const out = await hostPackageCheck.run(ctx, hostSubject(ctx), P({ assert: 'advisories' }), {} as never);
    expect(out.observed).toContain('CISA KEV was unavailable');
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

describe('host_package v2 fail-closed', () => {
  const env = fixtureEnvelope('ubuntu-24-04');

  it('counts held packages as installed: a held vulnerable openssh fails advisories', async () => {
    const old = withSourceVersion(env, 'openssh', '1:9.6p1-3ubuntu13');
    const held = sectionOf(old, 'packages').replace(/^ii (\t(openssh-server|openssh-client|openssh-sftp-server)\t)/gm, 'hi $1');
    const r = await run(decodeSnapshot(withSection(old, 'packages', held)), { assert: 'advisories' });
    expect(r.outcome).toBe('fail');
    expect(r.observed).toContain('openssh');
  });

  it('a failed packages section throws NO_PACKAGES for advisories and third_party', async () => {
    const snap = decodeSnapshot(withSection(env, 'packages', 'dpkg-query: error', 1));
    await expect(run(snap, { assert: 'advisories' })).rejects.toMatchObject({ code: 'NO_PACKAGES' });
    await expect(run(snap, { assert: 'third_party' })).rejects.toMatchObject({ code: 'NO_PACKAGES' });
  });

  it('reboot rc=1, garbage or a missing section is an ObservationError', async () => {
    await expect(run(decodeSnapshot(withSection(env, 'reboot', 'not-required\n', 1)), { assert: 'reboot' })).rejects.toBeInstanceOf(ObservationError);
    await expect(run(decodeSnapshot(withSection(env, 'reboot', 'maybe\n')), { assert: 'reboot' })).rejects.toBeInstanceOf(ObservationError);
    const missing = { ...env, sections: Object.fromEntries(Object.entries(env.sections).filter(([k]) => k !== 'reboot')) };
    await expect(run(decodeSnapshot(missing), { assert: 'reboot' })).rejects.toBeInstanceOf(ObservationError);
  });
});
