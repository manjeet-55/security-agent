import { z } from 'zod';
import type { PortState } from '../../net/tcp.js';
import { maxSeverity, SEVERITIES, type Severity } from '../../types.js';
import { mapLimit } from '../../util/pool.js';
import type { CheckType } from '../check-type.js';
import { subjectHostname, subjectId } from '../context.js';

const Port = z.number().int().min(1).max(65535);

export const portExposureParams = z.object({
  ports: z.array(z.object({ port: Port, service: z.string().min(1), severity: z.enum(SEVERITIES) })).min(1),
  /** Ports whose answer (open or refused) proves the host is reachable from this network. */
  liveness_ports: z.array(Port).default([80, 443]),
  concurrency: z.number().int().min(1).max(4).default(4),
});
export type PortExposureParams = z.infer<typeof portExposureParams>;

export function evaluatePorts(
  p: PortExposureParams,
  states: ReadonlyMap<number, PortState>,
  scanLabel: string,
): { outcome: 'pass' | 'fail' | 'unverifiable'; observed: string; severity?: Severity } {
  const open = p.ports.filter((x) => states.get(x.port) === 'open');
  if (open.length > 0) {
    return {
      outcome: 'fail',
      severity: maxSeverity(open.map((o) => o.severity)),
      observed: `open from network "${scanLabel}": ${open.map((o) => `${o.port}/${o.service}`).join(', ')}`,
    };
  }
  const anyRefused = p.ports.some((x) => states.get(x.port) === 'closed');
  const alive = p.liveness_ports.some((lp) => states.get(lp) === 'open' || states.get(lp) === 'closed');
  if (anyRefused || alive) {
    return { outcome: 'pass', observed: `none of ${p.ports.length} sensitive ports open from network "${scanLabel}" (refused or filtered)` };
  }
  return {
    outcome: 'unverifiable',
    observed: `no response on any probed port (including ${p.liveness_ports.join('/')}) from network "${scanLabel}"; the host may only accept allowlisted networks, so this proves nothing`,
  };
}

export const portExposureCheck: CheckType<PortExposureParams> = {
  type: 'port_exposure',
  supports: ['web', 'api', 'host'],
  params: portExposureParams,
  async run(ctx, subject, p) {
    const host = subjectHostname(subject);
    const ports = [...new Set([...p.ports.map((x) => x.port), ...p.liveness_ports])];
    const probed = await mapLimit(ports, p.concurrency, async (port) => [port, await ctx.net.tcp(host, port)] as const);
    const states = new Map<number, PortState>(probed);
    const evidence_id = await ctx.evidence.put('tcp', subjectId(subject), `TCP connect probe of ${ports.length} ports on ${host}`, {
      host,
      states: Object.fromEntries(states),
    });
    return { ...evaluatePorts(p, states, ctx.project.network.scan_label), evidence_id };
  },
};
