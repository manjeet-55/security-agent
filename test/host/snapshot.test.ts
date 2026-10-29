import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../src/checks/errors.js';
import { evaluateHostConfig, hostConfigParams } from '../../src/checks/types/host-config.js';
import { decodeSnapshot, REDACTION_LOST_SYNC_MARKER } from '../../src/host/snapshot.js';
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

  it('flags origins_unavailable when apt-cache policy failed or is missing, not when it succeeded', () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    expect(fixtureSnapshot('ubuntu-24-04').origins_unavailable).toBeUndefined();
    expect(decodeSnapshot(withSection(env, 'apt_policy', 'E: Could not open file', 100)).origins_unavailable).toBe(true);
    expect(decodeSnapshot(withSection(env, 'apt_policy', 'sh: apt-cache: not found', 127)).origins_unavailable).toBe(true);
    const missing = { ...env, sections: Object.fromEntries(Object.entries(env.sections).filter(([k]) => k !== 'apt_policy')) };
    expect(decodeSnapshot(missing).origins_unavailable).toBe(true);
    expect(decodeSnapshot(withSection(env, 'apt_policy', '')).origins_unavailable).toBeUndefined();
  });

  it('tolerates a missing dpkg (non-Debian host) but requires os-release', () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    expect(decodeSnapshot(withSection(env, 'packages', 'sh: 1: dpkg-query: not found', 127)).packages).toEqual([]);
    expect(() => decodeSnapshot(withSection(env, 'os_release', '', 1))).toThrow(ObservationError);
    expect(() => decodeSnapshot({ schema: 2 })).toThrow(/Not a secagent collector snapshot/);
  });

  describe('an nginx section the collector flagged as lost sync', () => {
    const env = fixtureEnvelope('ubuntu-24-04');
    const flagged = `http {\n\tssl_protocols TLSv1.2 TLSv1.3;\n${REDACTION_LOST_SYNC_MARKER}\n}\n`;
    const rule = hostConfigParams.parse({ rule: 'nginx_directive', directive: 'ssl_protocols', forbid_tokens: ['TLSv1'], when_absent: 'unverifiable' });

    it('is unreadable with the REDACTION_LOST_SYNC code, whatever the exit code', () => {
      for (const rc of [0, 1]) {
        expect(decodeSnapshot(withSection(env, 'nginx', flagged, rc)).nginx).toMatchObject({ state: 'error', code: 'REDACTION_LOST_SYNC' });
      }
    });

    it('makes the nginx check unverifiable instead of letting it pass on the surviving lines', () => {
      const snap = decodeSnapshot(withSection(env, 'nginx', flagged));
      expect(() => evaluateHostConfig(snap, rule)).toThrow(expect.objectContaining({ name: 'ObservationError', code: 'REDACTION_LOST_SYNC' }));
    });

    it('leaves clean nginx sections and the other sections alone', () => {
      expect(decodeSnapshot(withSection(env, 'nginx', 'http {\n\tssl_protocols TLSv1.2;\n}\n')).nginx.state).toBe('ok');
      const sshd = decodeSnapshot(withSection(env, 'sshd', `passwordauthentication no\n${REDACTION_LOST_SYNC_MARKER}\n`)).sshd;
      expect(sshd.state).toBe('ok');
      expect(fixtureSnapshot('ubuntu-24-04').nginx).not.toHaveProperty('code');
    });
  });
});
