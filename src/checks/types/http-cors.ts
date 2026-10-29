import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import type { HttpObservation } from '../../net/http.js';
import type { Severity } from '../../types.js';
import type { CheckType } from '../check-type.js';

export const httpCorsParams = z.object({});
export type HttpCorsParams = z.infer<typeof httpCorsParams>;

export interface CorsVerdict {
  outcome: 'pass' | 'fail';
  severity?: Severity;
  observed: string;
}

/**
 * Judges the CORS headers a server sent back to a request from an origin it has never heard of. Reflecting that origin lets any
 * website read the response from a visitor's browser; with credentials allowed, it reads them as the logged-in user.
 */
export function evaluateCors(obs: HttpObservation, probeOrigin: string): CorsVerdict {
  const acao = obs.headers['access-control-allow-origin']?.trim();
  const credentials = obs.headers['access-control-allow-credentials']?.trim().toLowerCase() === 'true';
  if (acao === undefined || acao === '') return { outcome: 'pass', observed: `no Access-Control-Allow-Origin for the unknown origin ${probeOrigin}` };
  if (acao === probeOrigin) {
    return credentials
      ? { outcome: 'fail', severity: 'high', observed: `reflects any Origin (${probeOrigin}) with Access-Control-Allow-Credentials: true, so any website can read responses as the logged-in user` }
      : { outcome: 'fail', severity: 'medium', observed: `reflects any Origin (${probeOrigin}), so any website can read responses from a visitor's browser` };
  }
  if (acao === 'null') return { outcome: 'fail', severity: 'medium', observed: 'Access-Control-Allow-Origin: null, which sandboxed pages and local files can use' };
  if (acao === '*' && credentials) return { outcome: 'fail', severity: 'medium', observed: 'Access-Control-Allow-Origin: * together with Allow-Credentials: true (browsers refuse it, and it shows the policy was not thought through)' };
  if (acao === '*') return { outcome: 'pass', observed: 'Access-Control-Allow-Origin: * without credentials (public, read-only data only)' };
  return { outcome: 'pass', observed: `allows only ${acao}, not the unknown origin` };
}

export const httpCorsCheck: CheckType<HttpCorsParams> = {
  type: 'http_cors',
  supports: ['web', 'api'],
  params: httpCorsParams,
  async run(ctx, subject) {
    if (subject.kind !== 'target') throw new Error('http_cors runs on targets only');
    const origin = `https://cors-probe-${randomBytes(4).toString('hex')}.example`;
    const obs = await ctx.net.http(subject.target.url, { headers: { Origin: origin } });
    const verdict = evaluateCors(obs, origin);
    // Headers only: the body is not needed to judge CORS.
    const evidence_id = await ctx.evidence.put('http', subject.target.id, `CORS probe from ${origin} → ${obs.status}`, {
      url: subject.target.url,
      origin,
      status: obs.status,
      access_control: Object.fromEntries(Object.entries(obs.headers).filter(([k]) => k.startsWith('access-control-') || k === 'vary')),
    });
    return { ...verdict, evidence_id };
  },
};
