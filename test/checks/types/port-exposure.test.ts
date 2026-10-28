import { describe, expect, it } from 'vitest';
import { evaluatePorts, portExposureCheck, portExposureParams } from '../../../src/checks/types/port-exposure.js';
import type { PortState } from '../../../src/net/tcp.js';
import { hostSubject, makeCtx } from '../../helpers/ctx.js';

const P = portExposureParams.parse({
  ports: [
    { port: 22, service: 'ssh', severity: 'medium' },
    { port: 5432, service: 'postgres', severity: 'high' },
  ],
});
const states = (entries: Array<[number, PortState]>) => new Map(entries);

describe('evaluatePorts', () => {
  it('fails open sensitive ports with the highest port severity', () => {
    const v = evaluatePorts(P, states([[22, 'open'], [5432, 'open'], [80, 'open'], [443, 'open']]), 'office');
    expect(v).toEqual({ outcome: 'fail', severity: 'high', observed: 'open from network "office": 22/ssh, 5432/postgres' });
  });
  it('passes when sensitive ports are filtered but the host answers on a liveness port', () => {
    expect(evaluatePorts(P, states([[22, 'timeout'], [5432, 'timeout'], [80, 'timeout'], [443, 'open']]), 'home').outcome).toBe('pass');
  });
  it('passes when a sensitive port is refused', () => {
    expect(evaluatePorts(P, states([[22, 'closed'], [5432, 'timeout'], [80, 'timeout'], [443, 'timeout']]), 'home').outcome).toBe('pass');
  });
  it('is unverifiable when nothing answers at all', () => {
    const v = evaluatePorts(P, states([[22, 'timeout'], [5432, 'timeout'], [80, 'timeout'], [443, 'timeout']]), 'home');
    expect(v.outcome).toBe('unverifiable');
    expect(v.observed).toContain('proves nothing');
  });
});

describe('port_exposure check', () => {
  it('probes the host address and stores every port state as evidence', async () => {
    const probed: string[] = [];
    const { ctx } = await makeCtx({
      tcp: async (host, port) => {
        probed.push(`${host}:${port}`);
        return port === 22 ? 'open' : 'closed';
      },
    });
    const out = await portExposureCheck.run(ctx, hostSubject(ctx), P, {} as never);
    expect(probed.sort()).toEqual(['203.0.113.10:22', '203.0.113.10:443', '203.0.113.10:5432', '203.0.113.10:80']);
    expect(out).toMatchObject({ outcome: 'fail', severity: 'medium' });
    expect(out.observed).toContain('test-net');
  });
});
