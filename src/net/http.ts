import http from 'node:http';
import https from 'node:https';
import type { LookupFunction } from 'node:net';
import { NetError, toNetError } from './errors.js';
import { stripBrackets } from './ip.js';

export interface CookieObservation {
  name: string;
  /** Lowercased attributes, e.g. ["secure", "httponly", "samesite=lax", "path=/"]. */
  attributes: string[];
  /** The Set-Cookie line with the value replaced by <redacted>. */
  redacted: string;
}

export interface HttpObservation {
  url: string;
  status: number;
  /** Lowercased header names; repeated headers joined with ", ". Set-Cookie is only in setCookies. */
  headers: Record<string, string>;
  setCookies: CookieObservation[];
  location?: string;
  /** Approximate wire size of the status line plus all response headers. */
  headerBytes: number;
  bodySnippet: string;
  bodyBytes: number;
  remoteAddress?: string;
}

export interface HttpOptions {
  family: 4 | 6;
  timeoutMs?: number;
  connectTimeoutMs?: number;
  method?: 'GET' | 'HEAD';
  headers?: Record<string, string>;
  maxBodyBytes?: number;
  /** Overrides DNS resolution; ScopedNet pins it to the addresses the scope guard validated. */
  lookup?: LookupFunction;
}

export const USER_AGENT = 'secagent/0.1 (+security self-assessment; authorised targets only)';
const SNIPPET_CHARS = 4096;

export function parseSetCookie(raw: string): CookieObservation {
  const [pair = '', ...rest] = raw.split(';').map((s) => s.trim());
  const attrs = rest.filter(Boolean);
  const eq = pair.indexOf('=');
  // Per RFC 6265bis a pair without "=" is a nameless cookie whose string is its value, so never keep it as the name.
  const name = eq === -1 ? '' : pair.slice(0, eq);
  return {
    name,
    attributes: attrs.map((a) => a.toLowerCase()),
    redacted: [eq === -1 ? '<redacted>' : `${name}=<redacted>`, ...attrs].join('; '),
  };
}

export function countHeaderBytes(statusLine: string, rawHeaders: readonly string[]): number {
  let total = Buffer.byteLength(`${statusLine}\r\n`);
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    total += Buffer.byteLength(`${rawHeaders[i]}: ${rawHeaders[i + 1]}\r\n`);
  }
  return total + 2;
}

/** One request, no redirect following, certificate errors ignored (the tls check judges certificates). */
export function httpRequest(url: string, opts: HttpOptions): Promise<HttpObservation> {
  const u = new URL(url);
  const isHttps = u.protocol === 'https:';
  const lib = isHttps ? https : http;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const connectTimeoutMs = opts.connectTimeoutMs ?? 5_000;
  const maxBody = opts.maxBodyBytes ?? 256 * 1024;

  return new Promise<HttpObservation>((resolve, reject) => {
    const req = lib.request({
      protocol: u.protocol,
      hostname: stripBrackets(u.hostname),
      port: u.port || undefined,
      path: `${u.pathname}${u.search}`,
      method: opts.method ?? 'GET',
      family: opts.family,
      headers: { 'user-agent': USER_AGENT, accept: '*/*', ...opts.headers },
      // Intentional: this probe only observes response headers of the project's own listed targets and sends no
      // credentials. Certificate trust is judged by the separate TLS check.
      rejectUnauthorized: false,
      agent: false,
      ...(opts.lookup ? { lookup: opts.lookup } : {}),
    });
    const totalTimer = setTimeout(
      () => req.destroy(new NetError('TIMEOUT', `No complete response from ${url} within ${timeoutMs}ms`)),
      timeoutMs,
    );
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      fn();
    };

    req.on('socket', (socket) => {
      const connectTimer = setTimeout(
        () => req.destroy(new NetError('CONNECT_TIMEOUT', `Could not connect to ${u.host} within ${connectTimeoutMs}ms`)),
        connectTimeoutMs,
      );
      socket.once(isHttps ? 'secureConnect' : 'connect', () => clearTimeout(connectTimer));
      socket.once('close', () => clearTimeout(connectTimer));
    });

    req.on('error', (e) => settle(() => reject(toNetError(e))));

    req.on('response', (res) => {
      const remoteAddress = res.socket?.remoteAddress;
      const chunks: Buffer[] = [];
      let bodyBytes = 0;
      res.on('data', (chunk: Buffer) => {
        if (bodyBytes < maxBody) chunks.push(chunk);
        bodyBytes += chunk.length;
        if (bodyBytes >= maxBody) res.destroy();
      });
      const finish = () =>
        settle(() => {
          const headers: Record<string, string> = {};
          for (const [key, value] of Object.entries(res.headers)) {
            if (key === 'set-cookie' || value === undefined) continue;
            headers[key] = Array.isArray(value) ? value.join(', ') : value;
          }
          resolve({
            url,
            status: res.statusCode ?? 0,
            headers,
            setCookies: (res.headers['set-cookie'] ?? []).map(parseSetCookie),
            ...(res.headers.location ? { location: res.headers.location } : {}),
            headerBytes: countHeaderBytes(`HTTP/${res.httpVersion} ${res.statusCode ?? 0} ${res.statusMessage ?? ''}`, res.rawHeaders),
            bodySnippet: Buffer.concat(chunks).toString('utf8').slice(0, SNIPPET_CHARS),
            bodyBytes,
            ...(remoteAddress ? { remoteAddress } : {}),
          });
        });
      res.on('end', finish);
      res.on('close', finish);
      // A body cut short still carries the status and headers the checks need.
      res.on('error', finish);
    });

    req.end();
  });
}
