import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../../src/checks/errors.js';
import { evaluateHostConfig, hostConfigCheck, hostConfigParams } from '../../../src/checks/types/host-config.js';
import { decodeSnapshot } from '../../../src/host/snapshot.js';
import { hostSubject, makeCtx } from '../../helpers/ctx.js';
import { fixtureEnvelope, fixtureSnapshot, readerFor, sectionOf, withSection } from '../../helpers/snapshots.js';

const P = (p: Record<string, unknown>) => hostConfigParams.parse(p);
const noble = fixtureSnapshot('ubuntu-24-04');
/** ss output with neither sshd nor nginx in it. */
const LISTEN_NONE = 'LISTEN 0 128 127.0.0.1:5432 0.0.0.0:* users:(("postgres",pid=9,fd=5))\n';

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
    const noOpenssh = sectionOf(env, 'packages').split('\n').filter((l) => !l.split('\t')[1]?.startsWith('openssh-server')).join('\n');
    const noSshd = decodeSnapshot(withSection(withSection(withSection(env, 'sshd', 'sh: 1: /usr/sbin/sshd: not found', 127), 'packages', noOpenssh), 'listening', LISTEN_NONE));
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

describe('evaluateHostConfig missing tools fail closed', () => {
  const env = fixtureEnvelope('ubuntu-24-04');
  const sshdRule = P({ rule: 'sshd_value', key: 'passwordauthentication', allowed: ['no'] });
  const nginxRule = P({ rule: 'nginx_directive', directive: 'server_tokens', equals: 'off', absent_default: 'on' });

  it('sshd rc 127 with openssh-server in dpkg is unverifiable', () => {
    const snap = decodeSnapshot(withSection(env, 'sshd', 'sh: 1: /usr/sbin/sshd: not found', 127));
    expect(() => evaluateHostConfig(snap, sshdRule)).toThrow(/openssh-server is installed/);
  });

  it('nginx rc 127 with nginx in dpkg is unverifiable; without it and as root it passes', () => {
    const snap = decodeSnapshot(withSection(env, 'nginx', 'sh: 1: nginx: not found', 127));
    expect(() => evaluateHostConfig(snap, nginxRule)).toThrow(ObservationError);
    const none = sectionOf(env, 'packages').split('\n').filter((l) => !/^ii \t(lib)?nginx|openresty/.test(l)).join('\n');
    const gone = decodeSnapshot(withSection(withSection(withSection(env, 'nginx', 'sh: 1: nginx: not found', 127), 'packages', none), 'listening', LISTEN_NONE));
    expect(evaluateHostConfig(gone, nginxRule).outcome).toBe('pass');
  });

  it('absent with an unusable package list is unverifiable', () => {
    const snap = decodeSnapshot(withSection(withSection(env, 'nginx', 'sh: 1: nginx: not found', 127), 'packages', 'sh: dpkg-query: not found', 127));
    expect(() => evaluateHostConfig(snap, nginxRule)).toThrow(/absence is unproven/);
  });

  it('any sshd/nginx error or absent when not root says to run the collector as root', () => {
    const user = withSection(env, 'uid', '1000\n');
    const a = decodeSnapshot(withSection(user, 'sshd', 'sh: sshd: not found', 127));
    expect(() => evaluateHostConfig(a, sshdRule)).toThrow(/run the collector as root/);
    const b = decodeSnapshot(withSection(user, 'nginx', 'nginx: permission denied', 1));
    expect(() => evaluateHostConfig(b, nginxRule)).toThrow(/run the collector as root/);
  });

  it('nginx_directive params need equals or forbid_tokens, and forbid_tokens may not be empty', () => {
    expect(() => hostConfigParams.parse({ rule: 'nginx_directive', directive: 'server_tokens' })).toThrow(/equals/);
    expect(() => hostConfigParams.parse({ rule: 'nginx_directive', directive: 'server_tokens', forbid_tokens: [] })).toThrow();
    expect(hostConfigParams.safeParse({ rule: 'nginx_directive', directive: 'server_tokens', forbid_tokens: [] }).success).toBe(false);
    expect(hostConfigParams.safeParse({ rule: 'nginx_directive', directive: 'server_tokens', forbid_tokens: ['on'] }).success).toBe(true);
  });
});

describe('a missing sshd/nginx passes only when nothing of that name is running', () => {
  const env = fixtureEnvelope('ubuntu-24-04');
  const sshdRule = P({ rule: 'sshd_value', key: 'passwordauthentication', allowed: ['no'] });
  const nginxRule = P({ rule: 'nginx_directive', directive: 'server_tokens', equals: 'off', absent_default: 'on' });
  const dropPackages = (re: RegExp) => sectionOf(env, 'packages').split('\n').filter((l) => !re.test(l)).join('\n');
  const sshAbsent = (listening: string, rc = 0) =>
    decodeSnapshot(withSection(withSection(withSection(env, 'sshd', 'sh: 1: /usr/sbin/sshd: not found', 127), 'packages', dropPackages(/\topenssh-server\t/)), 'listening', listening, rc));
  const nginxAbsent = (listening: string, rc = 0) =>
    decodeSnapshot(
      withSection(withSection(withSection(env, 'nginx', 'sh: 1: /usr/sbin/nginx: not found', 127), 'packages', dropPackages(/^[^\t]*\t(lib)?nginx|openresty/)), 'listening', listening, rc),
    );

  it('nginx: a socket owned by nginx proves it is running, so the missing binary is TOOL_MISSING', () => {
    const lst = 'LISTEN 0 511 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=812,fd=6))\nLISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=700,fd=3))\n';
    expect(() => evaluateHostConfig(nginxAbsent(lst), nginxRule)).toThrow(expect.objectContaining({ code: 'TOOL_MISSING' }));
    expect(() => evaluateHostConfig(nginxAbsent(lst), nginxRule)).toThrow(/443/);
  });

  it('sshd: a socket owned by sshd, or anything on port 22, proves it is running', () => {
    const sshdSocket = 'LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:(("sshd",pid=700,fd=3))\n';
    const port22 = 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("dropbear",pid=700,fd=3))\n';
    expect(() => evaluateHostConfig(sshAbsent(sshdSocket), sshdRule)).toThrow(expect.objectContaining({ code: 'TOOL_MISSING' }));
    expect(() => evaluateHostConfig(sshAbsent(port22), sshdRule)).toThrow(expect.objectContaining({ code: 'TOOL_MISSING' }));
  });

  it('an unreadable or missing listening section leaves the absence unproven', () => {
    for (const [text, rc] of [['sh: 1: ss: not found', 127], ['ss: permission denied', 1]] as const) {
      expect(() => evaluateHostConfig(nginxAbsent(text, rc), nginxRule)).toThrow(expect.objectContaining({ code: 'TOOL_MISSING' }));
      expect(() => evaluateHostConfig(sshAbsent(text, rc), sshdRule)).toThrow(expect.objectContaining({ code: 'TOOL_MISSING' }));
    }
    const noSection = { ...env, sections: Object.fromEntries(Object.entries(env.sections).filter(([k]) => k !== 'listening')) };
    const snap = decodeSnapshot(withSection(withSection(noSection, 'nginx', 'sh: 1: nginx: not found', 127), 'packages', dropPackages(/^[^\t]*\t(lib)?nginx|openresty/)));
    expect(() => evaluateHostConfig(snap, nginxRule)).toThrow(expect.objectContaining({ code: 'TOOL_MISSING' }));
  });

  it('passes when root, no package, and a readable listening section without that process', () => {
    expect(evaluateHostConfig(nginxAbsent(LISTEN_NONE), nginxRule)).toMatchObject({ outcome: 'pass', observed: 'nginx is not installed on this host' });
    expect(evaluateHostConfig(sshAbsent(LISTEN_NONE), sshdRule)).toMatchObject({ outcome: 'pass', observed: 'sshd is not installed on this host' });
    // an sshd socket does not make a missing nginx unprovable, and vice versa
    const onlySsh = 'LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=700,fd=3))\n';
    expect(evaluateHostConfig(nginxAbsent(onlySsh), nginxRule).outcome).toBe('pass');
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
