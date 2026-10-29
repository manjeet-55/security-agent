import { isIP } from 'node:net';
import { z } from 'zod';
import { stripBrackets } from '../../net/ip.js';
import type { DnsChain } from '../../net/scoped.js';
import type { CheckType } from '../check-type.js';
import { ObservationError } from '../errors.js';

export const dnsDanglingParams = z.object({});

export function evaluateChain(host: string, c: DnsChain): { outcome: 'pass' | 'fail'; observed: string } {
  if (c.chain.length === 0) return { outcome: 'pass', observed: `${host} has no CNAME` };
  const path = [host, ...c.chain].join(' → ');
  if (c.dangling) return { outcome: 'fail', observed: `${path}, and ${c.chain.at(-1)} does not exist: whoever claims that name controls ${host}` };
  return { outcome: 'pass', observed: `${path} resolves` };
}

export const dnsDanglingCheck: CheckType<z.infer<typeof dnsDanglingParams>> = {
  type: 'dns_dangling',
  supports: ['web', 'api'],
  params: dnsDanglingParams,
  async run(ctx, subject) {
    if (subject.kind !== 'target') throw new Error('dns_dangling runs on targets only');
    const host = stripBrackets(new URL(subject.target.url).hostname);
    if (isIP(host)) {
      const evidence_id = await ctx.evidence.put('note', subject.target.id, 'IP address, no DNS', { host });
      return { outcome: 'pass', observed: `${host} is an IP address, so there is no DNS record to take over`, evidence_id };
    }
    if (!ctx.net.dnsChain) throw new ObservationError('NO_DNS', 'DNS lookups are not available in this run.');
    const chain = await ctx.net.dnsChain(host);
    const evidence_id = await ctx.evidence.put('note', subject.target.id, `CNAME chain of ${host}`, { host, ...chain });
    return { ...evaluateChain(host, chain), evidence_id };
  },
};
