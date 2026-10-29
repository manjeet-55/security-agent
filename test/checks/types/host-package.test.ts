import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../../src/checks/errors.js';
import { distroSources, findFixable, hostPackageCheck, hostPackageParams, skippedSourceCount } from '../../../src/checks/types/host-package.js';
import { decodeSnapshot } from '../../../src/host/snapshot.js';
import { fixtureAdvisories, staleAdvisories } from '../../helpers/advisories.js';
import { hostSubject, makeCtx } from '../../helpers/ctx.js';
import { fixtureEnvelope, fixtureSnapshot, readerFor, sectionOf, withSection, withSourceVersion, withVendorOpenssh } from '../../helpers/snapshots.js';
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

  // The same predicate as the asserts: when origins can't be known (apt-cache policy failed, or the lists are empty) nothing is
  // excluded and nothing is reported as skipped, even if the snapshot still carries some origin data.
  it('skips nothing, and excludes nothing from distroSources, whenever originsProblem is set', () => {
    const vendor = decodeSnapshot(withVendorOpenssh(fixtureEnvelope('ubuntu-24-04'), 'https://packagecloud.io/acme/openssh/ubuntu'));
    expect(skippedSourceCount(vendor, 'noble')).toBe(3);
    expect(distroSources(vendor, 'noble').some((s) => s.name === 'openssh')).toBe(false);
    const failed = { ...vendor, origins_unavailable: true };
    expect(skippedSourceCount(failed, 'noble')).toBe(0);
    expect(distroSources(failed, 'noble').some((s) => s.name === 'openssh')).toBe(true);
    expect(distroSources(failed, 'noble')).toHaveLength(new Set(failed.packages.map((p) => p.source)).size);
  });
});

describe('host_package advisories freshness', () => {
  async function runWith(advisories: Awaited<ReturnType<typeof staleAdvisories>>, snap = fixtureSnapshot('ubuntu-24-04')) {
    const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(snap), advisories });
    const out = await hostPackageCheck.run(ctx, hostSubject(ctx), P({ assert: 'advisories' }), {} as never);
    return { out, record: await ctx.evidence.get(out.evidence_id as string) };
  }
  const warm = async (a: Awaited<ReturnType<typeof staleAdvisories>>) => {
    const snap = fixtureSnapshot('ubuntu-24-04');
    await findFixable(a, 'Ubuntu:24.04:LTS', distroSources(snap, 'noble'));
  };

  it('states the as-of date on a fresh pass and records it in the evidence', async () => {
    const { out, record } = await runWith(fixtureAdvisories(await tempDir()));
    expect(out.outcome).toBe('pass');
    expect(out.observed).toMatch(/; advisory data as of \d{4}-\d{2}-\d{2}$/);
    expect(out.observed).not.toContain('STALE');
    expect(JSON.stringify(record)).toMatch(/"advisories_stale":false/);
  });

  it('is unverifiable, not a pass, when the advisories came from an expired cached copy', async () => {
    const err = await runWith(await staleAdvisories(await tempDir(), warm)).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect(err).toMatchObject({ code: 'ADVISORIES_STALE' });
    expect((err as Error).message).toContain('advisory data as of 2026-10-20 is stale; run secagent learn');
  });

  it('is unverifiable, not a pass, when the advisory source cannot say how fresh its data is', async () => {
    const advisories = fixtureAdvisories(await tempDir());
    const blind = { ...advisories, track: async <T>(fn: () => Promise<T>) => ({ value: await fn(), freshness: undefined }) };
    const err = await runWith(blind).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect(err).toMatchObject({ code: 'ADVISORIES_FRESHNESS_UNKNOWN' });
  });

  it('still fails a vulnerable package when freshness is unknown, without claiming an as-of date', async () => {
    const old = decodeSnapshot(withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13'));
    const advisories = fixtureAdvisories(await tempDir());
    const blind = { ...advisories, track: async <T>(fn: () => Promise<T>) => ({ value: await fn(), freshness: undefined }) };
    const { out } = await runWith(blind, old);
    expect(out.outcome).toBe('fail');
    expect(out.observed).not.toContain('advisory data as of');
  });

  it('marks a fail STALE too', async () => {
    const old = decodeSnapshot(withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', '1:9.6p1-3ubuntu13'));
    const warmOld = async (a: Awaited<ReturnType<typeof staleAdvisories>>) => {
      await findFixable(a, 'Ubuntu:24.04:LTS', distroSources(old, 'noble'));
    };
    const { out, record } = await runWith(await staleAdvisories(await tempDir(), warmOld), old);
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('as of 2026-10-20, STALE');
    expect(JSON.stringify(record)).toMatch(/"advisories_as_of":"2026-10-20T00:00:00.000Z","advisories_stale":true/);
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

  it('does not check or vouch for a package from an unidentified mirror; it says it was skipped', async () => {
    const snap = decodeSnapshot(withVendorOpenssh(fixtureEnvelope('ubuntu-24-04'), 'https://packagecloud.io/acme/openssh/ubuntu'));
    const out = await run(snap, { assert: 'advisories' });
    expect(out.outcome).toBe('pass');
    expect(out.observed).toContain('3 non-distro packages not checked (see host-package-third-party)');
    expect(distroSources(snap, 'noble').some((s) => s.name === 'openssh')).toBe(false);
    expect(skippedSourceCount(snap, 'noble')).toBe(3);
  });

  it('is unverifiable when every package is served from an unidentified mirror', async () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const policy = sectionOf(env, 'apt_policy').replace(/^( {8}\d+ )http\S* \S+/gm, '$1https://packagecloud.io/acme/all/ubuntu noble/main');
    await expect(run(decodeSnapshot(withSection(env, 'apt_policy', policy)), { assert: 'advisories' })).rejects.toMatchObject({ code: 'NO_DISTRO_PACKAGES' });
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

describe('host_package advisories and dpkg states', () => {
  const withState = (state: string, version?: string) => {
    const env = version ? withSourceVersion(fixtureEnvelope('ubuntu-24-04'), 'openssh', version) : fixtureEnvelope('ubuntu-24-04');
    const pk = sectionOf(env, 'packages').replace(/^ii (\t(openssh-server|openssh-client|openssh-sftp-server)\t)/gm, `${state}$1`);
    return decodeSnapshot(withSection(env, 'packages', pk));
  };

  it.each(['iH ', 'iU ', 'iF ', 'iHR', 'iiR'])('does not pass while a checked package is in state "%s"', async (state) => {
    const err = await run(withState(state), { assert: 'advisories' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect(err).toMatchObject({ code: 'DPKG_STATE' });
    expect((err as Error).message).toContain('dpkg --configure -a');
    expect((err as Error).message).toContain('openssh-server');
  });

  it('still fails a vulnerable package in a half-installed state', async () => {
    const out = await run(withState('iU ', '1:9.6p1-3ubuntu13'), { assert: 'advisories' });
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('CVE-2024-6387');
  });

  it.each(['ii ', 'hi ', 'iW ', 'it '])('passes with the settled state "%s"', async (state) => {
    expect((await run(withState(state), { assert: 'advisories' })).outcome).toBe('pass');
  });

  it('ignores a broken package that is not from a distro repository (it is not checked anyway)', async () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const policy = `${sectionOf(env, 'apt_policy')}\nnginx:\n  Installed: 1.30.6-1~noble\n *** 1.30.6-1~noble 500\n        500 http://nginx.org/packages/ubuntu noble/nginx amd64 Packages\n        100 /var/lib/dpkg/status\n`;
    const packages = sectionOf(env, 'packages').replace(/^ii \tnginx\t[^\n]*$/m, 'iU \tnginx\t1.30.6-1~noble\tnginx\t1.30.6-1~noble');
    const snap = decodeSnapshot(withSection(withSection(env, 'apt_policy', policy), 'packages', packages));
    expect((await run(snap, { assert: 'advisories' })).outcome).toBe('pass');
  });
});

describe('host_package when apt-cache policy failed', () => {
  const env = fixtureEnvelope('ubuntu-24-04');
  const failed = (rc = 100) => decodeSnapshot(withSection(env, 'apt_policy', 'E: Could not open file /var/lib/apt/lists/x', rc));

  it('third_party is ORIGINS_UNAVAILABLE, not the "run apt-get update" advice', async () => {
    const err = await run(failed(), { assert: 'third_party' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect(err).toMatchObject({ code: 'ORIGINS_UNAVAILABLE', message: 'apt-cache policy failed; origins cannot be determined' });
    expect((err as Error).message).not.toContain('apt-get update');
  });

  it('a missing apt_policy section is the same', async () => {
    const missing = { ...env, sections: Object.fromEntries(Object.entries(env.sections).filter(([k]) => k !== 'apt_policy')) };
    await expect(run(decodeSnapshot(missing), { assert: 'third_party' })).rejects.toMatchObject({ code: 'ORIGINS_UNAVAILABLE' });
  });

  it('advisories are unverifiable, not a pass, when the packages cannot be attributed to a repository', async () => {
    const err = await run(failed(), { assert: 'advisories' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect(err).toMatchObject({ code: 'ORIGINS_UNAVAILABLE', message: 'apt-cache policy failed; origins cannot be determined' });
  });

  it('a vendor openssh build on a host whose apt-cache policy failed is unverifiable, not "no fixes pending"', async () => {
    const vendor = withVendorOpenssh(env, 'https://packagecloud.io/acme/openssh/ubuntu');
    const err = await run(decodeSnapshot(withSection(vendor, 'apt_policy', '', 100)), { assert: 'advisories' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect(err).toMatchObject({ code: 'ORIGINS_UNAVAILABLE' });
  });

  it('a missing apt_policy section makes advisories unverifiable too', async () => {
    const missing = { ...env, sections: Object.fromEntries(Object.entries(env.sections).filter(([k]) => k !== 'apt_policy')) };
    await expect(run(decodeSnapshot(missing), { assert: 'advisories' })).rejects.toMatchObject({ code: 'ORIGINS_UNAVAILABLE' });
  });

  it('advisories still fail a vulnerable package, and say origins could not be determined', async () => {
    const old = withSourceVersion(env, 'openssh', '1:9.6p1-3ubuntu13');
    const out = await run(decodeSnapshot(withSection(old, 'apt_policy', 'E: broken', 1)), { assert: 'advisories' });
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('apt-cache policy failed; origins cannot be determined');
  });

  const emptyLists = (e = env) => decodeSnapshot(withSection(e, 'apt_policy', sectionOf(e, 'apt_policy').replace(/^ {8}\d+ http\S*.*$/gm, '')));

  it('empty apt lists (policy succeeded) make advisories unverifiable, with the apt-get update advice', async () => {
    const err = await run(emptyLists(), { assert: 'advisories' }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect(err).toMatchObject({ code: 'APT_LISTS_EMPTY' });
    expect((err as Error).message).toContain('apt-get update');
  });

  it('empty apt lists still fail a vulnerable package, with the honest wording', async () => {
    const out = await run(emptyLists(withSourceVersion(env, 'openssh', '1:9.6p1-3ubuntu13')), { assert: 'advisories' });
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('apt package lists are empty');
  });

  it('a normal host still says distro source packages', async () => {
    expect((await run(fixtureSnapshot('ubuntu-24-04'), { assert: 'advisories' })).observed).toContain('distro source packages checked');
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

  it('lists a package served from an unidentified mirror as origin unknown and fails', async () => {
    const snap = decodeSnapshot(withVendorOpenssh(env, 'https://packagecloud.io/acme/openssh/ubuntu'));
    const out = await run(snap, { assert: 'third_party' });
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('openssh-server 1:9.7p1-1~vendor1 (origin unknown: https://packagecloud.io/acme/openssh/ubuntu noble/main amd64 Packages)');
    expect(out.observed).not.toMatch(/all \d+ packages come from/);
  });

  it('lists a package with no apt-cache entry as origin unknown', async () => {
    const policy = sectionOf(env, 'apt_policy').replace(/^openssh-server:\n(?:(?: .*)?\n)*/m, '');
    const out = await run(decodeSnapshot(withSection(env, 'apt_policy', policy)), { assert: 'third_party' });
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('openssh-server');
    expect(out.observed).toContain('origin unknown');
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
