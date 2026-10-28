import { readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import tls from 'node:tls';
import { afterEach } from 'vitest';

const FIXTURES = path.join(import.meta.dirname, '..', 'fixtures', 'tls');
export const TEST_KEY = readFileSync(path.join(FIXTURES, 'key.pem'));
export const TEST_CERT = readFileSync(path.join(FIXTURES, 'cert.pem'));

export interface Running {
  port: number;
  url: string;
  close(): Promise<void>;
}

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

function listen(server: http.Server | https.Server | tls.Server, scheme: string, host: string): Promise<Running> {
  return new Promise((resolve) => {
    server.listen(0, host, () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        port,
        url: `${scheme}://${host}:${port}`,
        close: () =>
          new Promise<void>((done) => {
            if ('closeAllConnections' in server) server.closeAllConnections();
            server.close(() => done());
          }),
      });
    });
  });
}

export function startHttp(handler: Handler, host = '127.0.0.1'): Promise<Running> {
  return listen(http.createServer(handler), 'http', host);
}

export function startHttps(handler: Handler, tlsOpts: tls.TlsOptions = {}, host = '127.0.0.1'): Promise<Running> {
  return listen(https.createServer({ key: TEST_KEY, cert: TEST_CERT, ...tlsOpts }, handler), 'https', host);
}

/** A bare TLS server that completes the handshake and closes. */
export function startTls(tlsOpts: tls.TlsOptions = {}, host = '127.0.0.1'): Promise<Running> {
  const server = tls.createServer({ key: TEST_KEY, cert: TEST_CERT, ...tlsOpts }, (socket) => socket.end());
  server.on('tlsClientError', () => {});
  return listen(server, 'tls', host);
}

/** Call at module or describe level: servers started through the returned track() are closed after each test. */
export function useServers(): (pending: Promise<Running>) => Promise<Running> {
  const running: Running[] = [];
  afterEach(async () => {
    await Promise.all(running.splice(0).map((s) => s.close()));
  });
  return async (pending) => {
    const server = await pending;
    running.push(server);
    return server;
  };
}
