import net from 'node:net';
import { stripBrackets } from './ip.js';

export type PortState = 'open' | 'closed' | 'timeout' | 'unreachable';

/** TCP connect only, never sends data. "closed" = refused (host answered); "timeout" = filtered or silent. */
export function tcpProbe(host: string, port: number, opts: { family: 4 | 6; timeoutMs?: number }): Promise<PortState> {
  const timeoutMs = opts.timeoutMs ?? 5_000;
  return new Promise((resolve) => {
    const socket = net.connect({ host: stripBrackets(host), port, family: opts.family });
    let settled = false;
    const finish = (state: PortState) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(state);
    };
    const timer = setTimeout(() => finish('timeout'), timeoutMs);
    socket.once('connect', () => finish('open'));
    socket.once('error', (e: NodeJS.ErrnoException) => finish(e.code === 'ECONNREFUSED' ? 'closed' : 'unreachable'));
  });
}
