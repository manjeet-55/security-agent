import { ScopeError, type Scope } from '../project/scope.js';
import { resolveCname, resolve4, resolve6 } from 'node:dns/promises';
import { NetError } from './errors.js';
import { pinnedLookup } from './ip.js';
import { httpRequest, type HttpObservation, type HttpOptions } from './http.js';
import { tcpProbe, type PortState } from './tcp.js';
import { tlsHandshake, type TlsObservation, type TlsOptions } from './tls.js';

/** The only network access a check gets. */
export interface NetClient {
  http(url: string, opts?: Pick<HttpOptions, 'method' | 'headers'>): Promise<HttpObservation>;
  tls(host: string, port: number, opts?: Pick<TlsOptions, 'minVersion' | 'maxVersion' | 'ciphers' | 'servername'>): Promise<TlsObservation>;
  tcp(host: string, port: number): Promise<PortState>;
  /** The CNAME chain of a listed hostname and whether its end exists. Optional: clients without it make DNS checks unverifiable. */
  dnsChain?(host: string): Promise<DnsChain>;
}

export interface DnsChain {
  /** The names the CNAMEs point through, in order; empty when the name has no CNAME. */
  chain: string[];
  /** True when the last name of the chain does not exist (NXDOMAIN). */
  dangling: boolean;
}

const NO_RECORD = new Set(['ENODATA', 'ENOTFOUND']);

async function exists(name: string): Promise<boolean> {
  for (const lookup of [resolve4, resolve6]) {
    try {
      if ((await lookup(name)).length > 0) return true;
    } catch (e) {
      const code = (e as NodeJS.ErrnoException).code ?? '';
      if (code === 'ENOTFOUND') return false;
      if (!NO_RECORD.has(code)) throw new NetError(code || 'DNS_FAILED', `DNS lookup of ${name} failed (${code})`);
    }
  }
  return false;
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
    if (Object.keys(opts.headers ?? {}).some((k) => k.toLowerCase() === 'host')) {
      throw new ScopeError('Overriding the Host header is not allowed');
    }
    const addresses = await this.scope.assertUrlAllowed(url);
    const lookup = pinnedLookup(addresses);
    return withRetry(() =>
      httpRequest(url, {
        family: this.family,
        timeoutMs: this.timeouts.totalMs,
        connectTimeoutMs: this.timeouts.connectMs,
        ...opts,
        lookup,
      }),
    );
  }

  async tls(
    host: string,
    port: number,
    opts: Pick<TlsOptions, 'minVersion' | 'maxVersion' | 'ciphers' | 'servername'> = {},
  ): Promise<TlsObservation> {
    const addresses = await this.scope.assertHostnameAllowed(host);
    if (opts.servername) await this.scope.assertHostnameAllowed(opts.servername);
    const lookup = pinnedLookup(addresses);
    return withRetry(() => tlsHandshake(host, port, { family: this.family, timeoutMs: this.timeouts.totalMs, ...opts, lookup }));
  }

  async dnsChain(host: string): Promise<DnsChain> {
    this.scope.assertListed(host);
    const chain: string[] = [];
    let current = host;
    for (let i = 0; i < 8; i += 1) {
      let next: string[];
      try {
        next = await resolveCname(current);
      } catch (e) {
        const code = (e as NodeJS.ErrnoException).code ?? '';
        if (NO_RECORD.has(code)) break;
        throw new NetError(code || 'DNS_FAILED', `CNAME lookup of ${current} failed (${code})`);
      }
      if (next.length === 0 || !next[0]) break;
      current = next[0];
      chain.push(current);
    }
    return { chain, dangling: chain.length > 0 && !(await exists(current)) };
  }

  async tcp(host: string, port: number): Promise<PortState> {
    const addresses = await this.scope.assertHostnameAllowed(host);
    return tcpProbe(host, port, { family: this.family, timeoutMs: this.timeouts.connectMs, lookup: pinnedLookup(addresses) });
  }
}
