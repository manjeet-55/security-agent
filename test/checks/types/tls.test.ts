import { describe, expect, it } from 'vitest';
import type { CheckContext } from '../../../src/checks/context.js';
import { ObservationError } from '../../../src/checks/errors.js';
import { evaluateCert, evaluateLegacy, evaluateModern, tlsCheck, tlsParams } from '../../../src/checks/types/tls.js';
import { EvidenceStore } from '../../../src/evidence/store.js';
import { ScopedNet } from '../../../src/net/scoped.js';
import { LEGACY_CIPHERS, type TlsObservation } from '../../../src/net/tls.js';
import { validateProject } from '../../../src/project/schema.js';
import { Scope } from '../../../src/project/scope.js';
import { NO_ADVISORIES, NO_SNAPSHOTS } from '../../helpers/ctx.js';
import { startTls, useServers } from '../../helpers/servers.js';
import { tempDir } from '../../helpers/tmp.js';

const STRICT_CIPHERS =
  'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

const obs = (partial: Partial<TlsObservation>): TlsObservation => ({
  host: 'app.example.com',
  port: 443,
  protocol: 'TLSv1.3',
  cipher: 'TLS_AES_256_GCM_SHA384',
  authorized: true,
  ...partial,
});
const cert = { subject: 'CN=app', issuer: 'CN=ca', valid_from: 'Jan  1 00:00:00 2026 GMT', days_remaining: 0, hostname_ok: true };

describe('evaluateLegacy', () => {
  it('fails when either legacy protocol is accepted', () => {
    const v = evaluateLegacy([
      { version: 'TLSv1', accepted: true, cipher: 'ECDHE-RSA-AES256-SHA' },
      { version: 'TLSv1.1', accepted: false, code: 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION' },
    ]);
    expect(v).toEqual({ outcome: 'fail', observed: 'server accepts TLSv1 (ECDHE-RSA-AES256-SHA)' });
  });
  it('passes when both are refused', () => {
    const v = evaluateLegacy([
      { version: 'TLSv1', accepted: false, code: 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION' },
      { version: 'TLSv1.1', accepted: false, code: 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION' },
    ]);
    expect(v.outcome).toBe('pass');
  });
});

describe('evaluateModern', () => {
  it('passes TLS 1.3 with weak TLS 1.2 refused', () => {
    expect(evaluateModern(obs({}), { accepted: false, code: 'ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE' }).outcome).toBe('pass');
  });
  it('fails a CBC default handshake', () => {
    expect(evaluateModern(obs({ protocol: 'TLSv1.2', cipher: 'ECDHE-RSA-AES256-SHA384' }), { accepted: true }).outcome).toBe('fail');
  });
  it('fails when weak TLS 1.2 ciphers are also accepted', () => {
    const v = evaluateModern(obs({}), { accepted: true, cipher: 'ECDHE-RSA-AES256-SHA384' });
    expect(v.observed).toContain('non-AEAD');
  });
});

describe('evaluateCert', () => {
  const now = new Date('2026-10-28T00:00:00Z');
  it('passes a trusted, matching certificate with time left', () => {
    expect(evaluateCert(obs({ cert: { ...cert, valid_to: 'Jan 26 00:00:00 2027 GMT' } }), 21, now).outcome).toBe('pass');
  });
  it('fails one expiring inside the renewal window', () => {
    expect(evaluateCert(obs({ cert: { ...cert, valid_to: 'Nov  7 00:00:00 2026 GMT' } }), 21, now).observed).toContain('expires in 10 day(s)');
  });
  it('fails an expired, untrusted, mismatched certificate with every reason', () => {
    const v = evaluateCert(
      obs({ authorized: false, authorization_error: 'CERT_HAS_EXPIRED', cert: { ...cert, valid_to: 'Sep 16 00:00:00 2026 GMT', hostname_ok: false, hostname_error: 'mismatch' } }),
      21,
      now,
    );
    expect(v.observed).toContain('not trusted (CERT_HAS_EXPIRED)');
    expect(v.observed).toContain('does not match the hostname');
    expect(v.observed).toContain('expired 42 day(s) ago');
  });
});

describe('tls check against real servers', () => {
  const track = useServers();

  async function setup(serverOpts: Parameters<typeof startTls>[0]) {
    const s = await track(startTls(serverOpts));
    const project = validateProject({ version: 1, name: 't', targets: [{ id: 'app', url: `https://127.0.0.1:${s.port}`, type: 'web', env: 'test' }] });
    const ctx: CheckContext = {
      project,
      net: new ScopedNet(new Scope(project), 4),
      evidence: new EvidenceStore(await tempDir(), 'test'),
      now: () => new Date(),
      snapshots: NO_SNAPSHOTS,
      advisories: NO_ADVISORIES,
      memo: new Map(),
    };
    const target = project.targets[0];
    if (!target) throw new Error('no target');
    return { ctx, subject: { kind: 'target' as const, target } };
  }
  const run = (ctx: CheckContext, subject: Awaited<ReturnType<typeof setup>>['subject'], assert: string) =>
    tlsCheck.run(ctx, subject, tlsParams.parse({ assert }), {} as never);

  it('an http:// address on its own port has no TLS to check: unverifiable with a plain explanation, and no handshake is tried', async () => {
    const project = validateProject({ version: 1, name: 't', targets: [{ id: 'app', url: 'http://127.0.0.1:8080', type: 'web', env: 'test' }] });
    const ctx: CheckContext = {
      project,
      net: { http: async () => { throw new Error('no http'); }, tls: async () => { throw new Error('a TLS handshake was tried'); }, tcp: async () => 'closed' },
      evidence: new EvidenceStore(await tempDir(), 'test'),
      now: () => new Date(),
      snapshots: NO_SNAPSHOTS,
      advisories: NO_ADVISORIES,
      memo: new Map(),
    };
    const target = project.targets[0]!;
    for (const assert of ['no_legacy', 'modern', 'cert']) {
      await expect(run(ctx, { kind: 'target', target }, assert)).rejects.toThrow(/http:\/\/ address on port 8080, so there is no TLS/);
      await expect(run(ctx, { kind: 'target', target }, assert)).rejects.toBeInstanceOf(ObservationError);
    }
  });

  it('fails no_legacy on a server accepting TLS 1.0', async () => {
    const { ctx, subject } = await setup({ minVersion: 'TLSv1', ciphers: LEGACY_CIPHERS });
    const out = await run(ctx, subject, 'no_legacy');
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('TLSv1');
  });

  it('passes no_legacy and modern on a strict server', async () => {
    const { ctx, subject } = await setup({ minVersion: 'TLSv1.2', ciphers: STRICT_CIPHERS });
    expect((await run(ctx, subject, 'no_legacy')).outcome).toBe('pass');
    expect((await run(ctx, subject, 'modern')).outcome).toBe('pass');
  });

  it('fails modern when weak TLS 1.2 ciphers are accepted', async () => {
    const { ctx, subject } = await setup({ minVersion: 'TLSv1.2', ciphers: 'DEFAULT:@SECLEVEL=0' });
    expect((await run(ctx, subject, 'modern')).observed).toContain('non-AEAD');
  });

  it('fails cert on a self-signed certificate', async () => {
    const { ctx, subject } = await setup({ minVersion: 'TLSv1.2' });
    expect((await run(ctx, subject, 'cert')).observed).toContain('not trusted');
  });
});
