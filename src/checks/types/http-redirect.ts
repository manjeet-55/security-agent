import { z } from 'zod';
import { NetError } from '../../net/errors.js';
import type { HttpObservation } from '../../net/http.js';
import { stripBrackets } from '../../net/ip.js';
import type { CheckType } from '../check-type.js';

export const httpRedirectParams = z.object({
  accepted_statuses: z.array(z.number().int()).default([301, 308]),
});
export type HttpRedirectParams = z.infer<typeof httpRedirectParams>;

export function evaluateRedirect(
  obs: HttpObservation,
  expectedHostname: string,
  p: HttpRedirectParams,
): { outcome: 'pass' | 'fail'; observed: string } {
  if (obs.status < 300 || obs.status >= 400 || !obs.location) {
    return { outcome: 'fail', observed: `http:// answered ${obs.status} without redirecting to https:// (content is served over plaintext)` };
  }
  let location: URL;
  try {
    location = new URL(obs.location, obs.url);
  } catch {
    return { outcome: 'fail', observed: `redirect Location is not a valid URL: ${obs.location}` };
  }
  if (location.protocol !== 'https:') {
    return { outcome: 'fail', observed: `http:// redirects to ${location.href}, which is not https://` };
  }
  if (stripBrackets(location.hostname).toLowerCase() !== expectedHostname.toLowerCase()) {
    return {
      outcome: 'fail',
      observed: `http:// redirects to a different host (${location.hostname}); the first hop should stay on ${expectedHostname} so HSTS applies`,
    };
  }
  if (!p.accepted_statuses.includes(obs.status)) {
    return { outcome: 'fail', observed: `http:// redirects to https:// with ${obs.status}; use a permanent redirect (${p.accepted_statuses.join('/')})` };
  }
  return { outcome: 'pass', observed: `http:// → ${obs.status} → ${location.href}` };
}

export const httpRedirectCheck: CheckType<HttpRedirectParams> = {
  type: 'http_redirect',
  supports: ['web', 'api'],
  params: httpRedirectParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'target') throw new Error('http_redirect runs on targets only');
    const target = new URL(subject.target.url);
    const httpUrl = target.protocol === 'http:' ? subject.target.url : `http://${target.hostname}/`;
    let obs: HttpObservation;
    try {
      obs = await ctx.net.http(httpUrl);
    } catch (e) {
      if (e instanceof NetError && e.code === 'ECONNREFUSED') {
        const evidence_id = await ctx.evidence.put('note', subject.target.id, `${httpUrl} refused the connection`, { url: httpUrl, code: e.code });
        return { outcome: 'pass', observed: 'port 80 refuses connections, so nothing is served over plaintext HTTP', evidence_id };
      }
      throw e;
    }
    const evidence_id = await ctx.evidence.put('http', subject.target.id, `GET ${httpUrl} → ${obs.status}`, obs);
    return { ...evaluateRedirect(obs, stripBrackets(target.hostname), p), evidence_id };
  },
};
