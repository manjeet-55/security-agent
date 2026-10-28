import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../../src/checks/errors.js';
import { evaluateHostConfig, hostConfigCheck, hostConfigParams } from '../../../src/checks/types/host-config.js';
import { decodeSnapshot } from '../../../src/host/snapshot.js';
import { hostSubject, makeCtx } from '../../helpers/ctx.js';
import { fixtureEnvelope, fixtureSnapshot, readerFor, withSection } from '../../helpers/snapshots.js';

const P = (p: Record<string, unknown>) => hostConfigParams.parse(p);
const noble = fixtureSnapshot('ubuntu-24-04');

describe('evaluateHostConfig on a real Ubuntu 24.04 snapshot', () => {
  it('checks sshd -T values', () => {
    expect(evaluateHostConfig(noble, P({ rule: 'sshd_value', key: 'PasswordAuthentication', allowed: ['no'] }))).toMatchObject({
      outcome: 'fail',
      observed: 'passwordauthentication yes (expected no)',
    });
    expect(
      evaluateHostConfig(noble, P({ rule: 'sshd_value', key: 'permitrootlogin', allowed: ['no', 'prohibit-password', 'without-password'] })).outcome,
    ).toBe('pass');
  });

  it('checks nginx directives, applying defaults and ignoring comments', () => {
    expect(evaluateHostConfig(noble, P({ rule: 'nginx_directive', directive: 'server_tokens', equals: 'off', absent_default: 'on' }))).toMatchObject({
      outcome: 'fail',
      observed: 'server_tokens on (not set; nginx default "on" applies) (expected off)',
    });
    expect(
      evaluateHostConfig(noble, P({ rule: 'nginx_directive', directive: 'ssl_protocols', forbid_tokens: ['SSLv3', 'TLSv1', 'TLSv1.1'] })).observed,
    ).toBe('ssl_protocols allows TLSv1, TLSv1.1');
  });

  it('checks listening sockets and unattended-upgrades', () => {
    expect(evaluateHostConfig(noble, P({ rule: 'listening', forbid_public_ports: [5432, 6379] })).outcome).toBe('pass');
    expect(evaluateHostConfig(noble, P({ rule: 'listening', forbid_public_ports: [22] })).observed).toContain('22/sshd');
    expect(evaluateHostConfig(noble, P({ rule: 'auto_upgrades' })).outcome).toBe('pass');
  });
});

describe('evaluateHostConfig edge cases', () => {
  const env = fixtureEnvelope('ubuntu-24-04');

  it('passes when sshd or nginx is not installed, and is unverifiable when unreadable', () => {
    const noSshd = decodeSnapshot(withSection(env, 'sshd', 'sh: 1: /usr/sbin/sshd: not found', 127));
    expect(evaluateHostConfig(noSshd, P({ rule: 'sshd_value', key: 'passwordauthentication', allowed: ['no'] })).observed).toBe(
      'sshd is not installed on this host',
    );
    const notRoot = decodeSnapshot(withSection(env, 'sshd', 'sshd: no hostkeys available -- exiting.', 255));
    expect(() => evaluateHostConfig(notRoot, P({ rule: 'sshd_value', key: 'passwordauthentication', allowed: ['no'] }))).toThrow(ObservationError);
  });

  it('treats an unset ssl_protocols as unverifiable, a missing ss as unverifiable, and a missing unattended-upgrades as fail', () => {
    const noProtocols = decodeSnapshot(withSection(env, 'nginx', 'http { server { listen 80; } }'));
    expect(() => evaluateHostConfig(noProtocols, P({ rule: 'nginx_directive', directive: 'ssl_protocols', forbid_tokens: ['TLSv1'] }))).toThrow(
      /depends on the nginx version/,
    );
    const noSs = decodeSnapshot(withSection(env, 'listening', 'sh: 1: ss: not found', 127));
    expect(() => evaluateHostConfig(noSs, P({ rule: 'listening', forbid_public_ports: [5432] }))).toThrow(ObservationError);
    const noUu = decodeSnapshot(withSection(env, 'auto_upgrades', '', 1));
    expect(evaluateHostConfig(noUu, P({ rule: 'auto_upgrades' })).observed).toBe('unattended-upgrades is not installed');
  });
});

describe('host_config check', () => {
  it('reads the snapshot through the context and stores only an excerpt as evidence', async () => {
    const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(noble) });
    const out = await hostConfigCheck.run(ctx, hostSubject(ctx), P({ rule: 'sshd_value', key: 'passwordauthentication', allowed: ['no'] }), {} as never);
    expect(out.outcome).toBe('fail');
    const ev = await ctx.evidence.get(out.evidence_id);
    expect(ev.kind).toBe('snapshot');
    expect(ev.data).toEqual({ snapshot: '20261028T143146Z.json', collected_at: '2026-10-28T14:31:46Z', rule: 'sshd_value', excerpt: { passwordauthentication: 'yes' } });
  });
});
