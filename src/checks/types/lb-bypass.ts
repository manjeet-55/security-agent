import { z } from 'zod';
import { NetError } from '../../net/errors.js';
import { isPrivateAddress, stripBrackets } from '../../net/ip.js';
import type { CheckType } from '../check-type.js';

export const lbBypassParams = z.object({});
export type LbBypassParams = z.infer<typeof lbBypassParams>;

export interface DirectAttempt {
  url: string;
  status?: number;
  code?: string;
}

const REFUSED = new Set(['ECONNREFUSED', 'ECONNRESET', 'EPROTO', 'ERR_SSL_WRONG_VERSION_NUMBER']);

/** Did the server answer on its own address? A refusal on both ports is a pass; a timeout proves nothing from this network. */
export function evaluateDirect(attempts: readonly DirectAttempt[], scanLabel: string): { outcome: 'pass' | 'fail' | 'unverifiable'; observed: string } {
  const answered = attempts.filter((a) => a.status !== undefined);
  if (answered.length > 0) {
    return {
      outcome: 'fail',
      observed: `answers directly on its own address (${answered.map((a) => `${a.url} → ${a.status}`).join(', ')}), so clients can reach it without the load balancer, its WAF and its certificate`,
    };
  }
  if (attempts.every((a) => a.code !== undefined && REFUSED.has(a.code))) return { outcome: 'pass', observed: `refuses HTTP and HTTPS on its own address from network "${scanLabel}"` };
  return {
    outcome: 'unverifiable',
    observed: `no answer on its own address from network "${scanLabel}" (${attempts.map((a) => `${a.url}: ${a.code ?? 'no answer'}`).join(', ')}); from another network it may still answer`,
  };
}

export const lbBypassCheck: CheckType<LbBypassParams> = {
  type: 'lb_bypass',
  supports: ['host'],
  params: lbBypassParams,
  async run(ctx, subject) {
    if (subject.kind !== 'host') throw new Error('lb_bypass runs on hosts only');
    const { host } = subject;
    const address = stripBrackets(host.address);
    if (host.serves.length === 0) {
      const evidence_id = await ctx.evidence.put('note', host.name, 'not behind a load balancer per project.yaml', { serves: [] });
      return { outcome: 'pass', observed: 'project.yaml lists no sites this server serves through a load balancer (serves:), so there is nothing to bypass', evidence_id };
    }
    if (isPrivateAddress(address) && /^[\d.:a-f]+$/i.test(address)) {
      const evidence_id = await ctx.evidence.put('note', host.name, 'private address', { address });
      return { outcome: 'pass', observed: `${address} is a private address, so the internet cannot reach it directly`, evidence_id };
    }
    const hostPart = address.includes(':') ? `[${address}]` : address;
    const attempts: DirectAttempt[] = [];
    for (const url of [`https://${hostPart}/`, `http://${hostPart}/`]) {
      try {
        attempts.push({ url, status: (await ctx.net.http(url, { method: 'HEAD' })).status });
      } catch (e) {
        if (!(e instanceof NetError)) throw e;
        attempts.push({ url, code: e.code });
      }
    }
    const evidence_id = await ctx.evidence.put('http', host.name, `direct-address probe of ${address}`, { address, serves: host.serves, attempts });
    return { ...evaluateDirect(attempts, ctx.project.network.scan_label), evidence_id };
  },
};
