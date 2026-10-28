import type { Scope } from '../project/scope.js';
import { NetError } from './errors.js';
import { httpRequest, type HttpObservation, type HttpOptions } from './http.js';
import { tcpProbe, type PortState } from './tcp.js';
import { tlsHandshake, type TlsObservation, type TlsOptions } from './tls.js';

/** The only network access a check gets. */
export interface NetClient {
  http(url: string, opts?: Pick<HttpOptions, 'method' | 'headers'>): Promise<HttpObservation>;
  tls(host: string, port: number, opts?: Pick<TlsOptions, 'minVersion' | 'maxVersion' | 'ciphers' | 'servername'>): Promise<TlsObservation>;
  tcp(host: string, port: number): Promise<PortState>;
}

const RETRYABLE = new Set(['TIMEOUT', 'CONNECT_TIMEOUT']);

export async function withRetry<T>(fn: () => Promise<T>, retries = 1): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await fn();
    } catch (e) {
      if (attempt >= retries || !(e instanceof NetError) || !RETRYABLE.has(e.code)) throw e;
    }
  }
}

/** Every call is scope-checked first, so no check can reach a host that project.yaml does not list. */
export class ScopedNet implements NetClient {
  constructor(
    private readonly scope: Scope,
    private readonly family: 4 | 6,
    private readonly timeouts: { totalMs: number; connectMs: number } = { totalMs: 10_000, connectMs: 5_000 },
  ) {}

  async http(url: string, opts: Pick<HttpOptions, 'method' | 'headers'> = {}): Promise<HttpObservation> {
    await this.scope.assertUrlAllowed(url);
    return withRetry(() =>
      httpRequest(url, { family: this.family, timeoutMs: this.timeouts.totalMs, connectTimeoutMs: this.timeouts.connectMs, ...opts }),
    );
  }

  async tls(
    host: string,
    port: number,
    opts: Pick<TlsOptions, 'minVersion' | 'maxVersion' | 'ciphers' | 'servername'> = {},
  ): Promise<TlsObservation> {
    await this.scope.assertHostnameAllowed(host);
    return withRetry(() => tlsHandshake(host, port, { family: this.family, timeoutMs: this.timeouts.totalMs, ...opts }));
  }

  async tcp(host: string, port: number): Promise<PortState> {
    await this.scope.assertHostnameAllowed(host);
    return tcpProbe(host, port, { family: this.family, timeoutMs: this.timeouts.connectMs });
  }
}
