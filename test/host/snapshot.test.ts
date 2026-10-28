import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../src/checks/errors.js';
import { decodeSnapshot } from '../../src/host/snapshot.js';
import { fixtureEnvelope, fixtureSnapshot, withSection } from '../helpers/snapshots.js';

describe('decodeSnapshot (real container outputs)', () => {
  it('decodes Ubuntu 24.04', () => {
    const s = fixtureSnapshot('ubuntu-24-04');
    expect(s.os).toMatchObject({ id: 'ubuntu', version_id: '24.04', codename: 'noble' });
    expect(s.is_root).toBe(true);
    expect(s.packages.find((p) => p.name === 'openssh-server')).toMatchObject({ source: 'openssh', source_version: '1:9.6p1-3ubuntu13.20' });
    expect(s.origins['openssh-server']?.sources.some((x) => x.includes('noble-security/main'))).toBe(true);
    expect(s.sshd).toMatchObject({ state: 'ok', value: { passwordauthentication: 'yes', permitrootlogin: 'without-password' } });
    expect(s.nginx.state).toBe('ok');
    expect(s.listening.state === 'ok' && s.listening.value.some((l) => l.port === 22)).toBe(true);
    expect(s.auto_upgrades).toEqual({ enabled: true, installed: true });
    expect(s.reboot).toEqual({ required: false, packages: [] });
  });

  it('decodes Ubuntu 22.04 and Debian 12', () => {
    expect(fixtureSnapshot('ubuntu-22-04').os.codename).toBe('jammy');
    const d = fixtureSnapshot('debian-12');
    expect(d.os).toMatchObject({ id: 'debian', version_id: '12', codename: 'bookworm' });
    expect(d.packages.find((p) => p.name === 'openssh-server')?.source_version).toBe('1:9.2p1-2+deb12u10');
  });

  it('contains no planted secrets', () => {
    for (const name of ['ubuntu-24-04', 'ubuntu-22-04', 'debian-12'] as const) {
      const s = fixtureSnapshot(name);
      const text = s.nginx.state === 'ok' ? s.nginx.value : '';
      expect(text).toContain('<redacted>');
      for (const secret of ['s3cretA1value', 's3cretB2value', 'abcdefghijklmnop12345']) expect(text).not.toContain(secret);
    }
  });

  it('maps exit code 127 to absent and other failures to error', () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const absent = decodeSnapshot(withSection(env, 'sshd', 'sh: 1: /usr/sbin/sshd: not found', 127));
    expect(absent.sshd).toEqual({ state: 'absent', reason: 'sh: 1: /usr/sbin/sshd: not found' });
    const error = decodeSnapshot(withSection(env, 'sshd', 'sshd: no hostkeys available -- exiting.', 255));
    expect(error.sshd).toEqual({ state: 'error', reason: 'sshd: no hostkeys available -- exiting.' });
  });

  it('tolerates a missing dpkg (non-Debian host) but requires os-release', () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    expect(decodeSnapshot(withSection(env, 'packages', 'sh: 1: dpkg-query: not found', 127)).packages).toEqual([]);
    expect(() => decodeSnapshot(withSection(env, 'os_release', '', 1))).toThrow(ObservationError);
    expect(() => decodeSnapshot({ schema: 2 })).toThrow(/Not a secagent collector snapshot/);
  });
});
