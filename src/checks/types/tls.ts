import type { SecureVersion } from 'node:tls';
import { z } from 'zod';
import { NetError } from '../../net/errors.js';
import { stripBrackets } from '../../net/ip.js';
import type { NetClient } from '../../net/scoped.js';
import { isHandshakeRejection, LEGACY_CIPHERS, NON_AEAD_TLS12_CIPHERS, type TlsObservation } from '../../net/tls.js';
import type { CheckType } from '../check-type.js';
import { memoize } from '../context.js';
import { ObservationError } from '../errors.js';

export const tlsParams = z.object({
  assert: z.enum(['no_legacy', 'modern', 'cert']),
  port: z.number().int().min(1).max(65535).optional(),
  min_cert_days: z.number().int().nonnegative().default(21),
});
export type TlsParams = z.infer<typeof tlsParams>;

type Verdict = { outcome: 'pass' | 'fail'; observed: string };

export interface LegacyAttempt {
  version: SecureVersion;
  accepted: boolean;
  cipher?: string | null;
  code?: string;
}

export function evaluateLegacy(attempts: readonly LegacyAttempt[]): Verdict {
  const accepted = attempts.filter((a) => a.accepted);
  if (accepted.length > 0) {
    return { outcome: 'fail', observed: `server accepts ${accepted.map((a) => `${a.version}${a.cipher ? ` (${a.cipher})` : ''}`).join(' and ')}` };
  }
  const codes = [...new Set(attempts.map((a) => a.code).filter(Boolean))].join(', ');
  return { outcome: 'pass', observed: `${attempts.map((a) => a.version).join(' and ')} refused (${codes})` };
}

const AEAD = /GCM|CHACHA20|CCM/i;

export function evaluateModern(def: TlsObservation, weak: { accepted: boolean; cipher?: string | null; code?: string }): Verdict {
  const negotiated = `${def.protocol ?? 'unknown protocol'} with ${def.cipher ?? 'unknown cipher'}`;
  const modernDefault = def.protocol === 'TLSv1.3' || (def.protocol === 'TLSv1.2' && AEAD.test(def.cipher ?? ''));
  if (!modernDefault) {
    return { outcome: 'fail', observed: `default handshake negotiated ${negotiated}; expected TLS 1.3, or TLS 1.2 with an AEAD (GCM/CHACHA20) cipher` };
  }
  if (weak.accepted) {
    return { outcome: 'fail', observed: `default handshake is ${negotiated}, but the server also accepts the non-AEAD TLS 1.2 cipher ${weak.cipher ?? 'unknown'}` };
  }
  return { outcome: 'pass', observed: `default handshake ${negotiated}; non-AEAD TLS 1.2 ciphers refused` };
}

export function evaluateCert(obs: TlsObservation, minDays: number, now: Date): Verdict {
  const cert = obs.cert;
  if (!cert) return { outcome: 'fail', observed: 'server presented no certificate' };
  const days = Math.floor((Date.parse(cert.valid_to) - now.getTime()) / 86_400_000);
  const problems: string[] = [];
  if (!obs.authorized) problems.push(`not trusted (${obs.authorization_error ?? 'unknown reason'})`);
  if (!cert.hostname_ok) problems.push(`does not match the hostname (${cert.hostname_error ?? 'mismatch'})`);
  if (days < 0) problems.push(`expired ${-days} day(s) ago (${cert.valid_to})`);
  else if (days < minDays) problems.push(`expires in ${days} day(s) (${cert.valid_to}); renew at least ${minDays} days ahead`);
  if (problems.length > 0) return { outcome: 'fail', observed: `certificate ${problems.join('; ')}` };
  return { outcome: 'pass', observed: `certificate trusted, matches hostname, ${days} days left (until ${cert.valid_to})` };
}

async function attempt(
  net: NetClient,
  host: string,
  port: number,
  opts: { minVersion: SecureVersion; maxVersion: SecureVersion; ciphers: string },
): Promise<{ accepted: boolean; cipher?: string | null; code?: string }> {
  try {
    const result = await net.tls(host, port, opts);
    return { accepted: true, cipher: result.cipher };
  } catch (e) {
    if (e instanceof NetError && isHandshakeRejection(e.code)) return { accepted: false, code: e.code };
    throw e;
  }
}

export const tlsCheck: CheckType<TlsParams> = {
  type: 'tls',
  supports: ['web', 'api'],
  params: tlsParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'target') throw new Error('tls runs on targets only');
    const url = new URL(subject.target.url);
    const host = stripBrackets(url.hostname);
    if (p.port === undefined && url.protocol === 'http:' && url.port !== '') {
      // The address names a plain-HTTP port; a TLS handshake there only produces a protocol error nobody can act on.
      throw new ObservationError(
        'NOT_HTTPS',
        `This target is an http:// address on port ${url.port}, so there is no TLS on it to check. Add its https:// address as a target to check the certificate and protocols.`,
      );
    }
    const port = p.port ?? (url.port ? Number(url.port) : 443);
    const id = subject.target.id;

    if (p.assert === 'no_legacy') {
      const attempts: LegacyAttempt[] = [];
      for (const version of ['TLSv1', 'TLSv1.1'] as const) {
        attempts.push({ version, ...(await attempt(ctx.net, host, port, { minVersion: version, maxVersion: version, ciphers: LEGACY_CIPHERS })) });
      }
      const evidence_id = await ctx.evidence.put('tls', id, `legacy protocol probe ${host}:${port}`, { host, port, attempts });
      return { ...evaluateLegacy(attempts), evidence_id };
    }

    const def = await memoize(ctx, `TLS ${host}:${port}`, () => ctx.net.tls(host, port));
    if (p.assert === 'modern') {
      const weak = await attempt(ctx.net, host, port, { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', ciphers: NON_AEAD_TLS12_CIPHERS });
      const evidence_id = await ctx.evidence.put('tls', id, `cipher probe ${host}:${port}`, { default: def, weak_tls12_probe: weak });
      return { ...evaluateModern(def, weak), evidence_id };
    }
    const evidence_id = await ctx.evidence.put('tls', id, `certificate ${host}:${port}`, def);
    return { ...evaluateCert(def, p.min_cert_days, ctx.now()), evidence_id };
  },
};
