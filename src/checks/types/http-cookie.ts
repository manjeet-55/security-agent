import { z } from 'zod';
import type { HttpObservation } from '../../net/http.js';
import type { CheckType } from '../check-type.js';
import { getPage } from '../context.js';

export const httpCookieParams = z.object({
  require: z.array(z.enum(['secure', 'httponly', 'samesite'])).min(1).default(['secure', 'httponly', 'samesite']),
});
export type HttpCookieParams = z.infer<typeof httpCookieParams>;

export function evaluateCookies(obs: HttpObservation, p: HttpCookieParams): { outcome: 'pass' | 'fail'; observed: string } {
  if (obs.setCookies.length === 0) return { outcome: 'pass', observed: 'no cookies set on this response' };
  const problems: string[] = [];
  for (const cookie of obs.setCookies) {
    const missing = p.require.filter((flag) => !cookie.attributes.some((a) => a === flag || a.startsWith(`${flag}=`)));
    if (missing.length > 0) problems.push(`${cookie.name} missing ${missing.join(', ')}`);
  }
  if (problems.length > 0) return { outcome: 'fail', observed: problems.join('; ') };
  return { outcome: 'pass', observed: `${obs.setCookies.length} cookie(s) set, all with ${p.require.join(', ')}` };
}

export const httpCookieCheck: CheckType<HttpCookieParams> = {
  type: 'http_cookie',
  supports: ['web', 'api'],
  params: httpCookieParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'target') throw new Error('http_cookie runs on targets only');
    const page = await getPage(ctx, subject);
    return { ...evaluateCookies(page.obs, p), evidence_id: page.evidenceId };
  },
};
