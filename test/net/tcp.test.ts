import { describe, expect, it } from 'vitest';
import { tcpProbe } from '../../src/net/tcp.js';
import { startHttp } from '../helpers/servers.js';

describe('tcpProbe', () => {
  it('reports open for a listening port and closed once it stops', async () => {
    const s = await startHttp((_req, res) => res.end());
    expect(await tcpProbe('127.0.0.1', s.port, { family: 4 })).toBe('open');
    await s.close();
    expect(await tcpProbe('127.0.0.1', s.port, { family: 4 })).toBe('closed');
  });

  it('never throws for a silent address', async () => {
    const state = await tcpProbe('10.255.255.1', 9, { family: 4, timeoutMs: 300 });
    expect(['timeout', 'unreachable']).toContain(state);
  });
});
