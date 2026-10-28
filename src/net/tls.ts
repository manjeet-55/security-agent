import { isIP, type LookupFunction } from 'node:net';
import tls, { type PeerCertificate, type SecureVersion } from 'node:tls';
import { NetError, toNetError } from './errors.js';
import { stripBrackets } from './ip.js';

/** Lets the client offer TLS 1.0/1.1 suites that OpenSSL 3 disables at the default security level. */
export const LEGACY_CIPHERS = 'DEFAULT@SECLEVEL=0';
/** TLS 1.2 suites without AEAD (CBC etc.). "!AEAD" is not a working exclusion in OpenSSL 3.5. */
export const NON_AEAD_TLS12_CIPHERS = 'DEFAULT:!AESGCM:!CHACHA20:!AESCCM:@SECLEVEL=0';

export interface CertInfo {
  subject: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  subjectaltname?: string;
  days_remaining: number;
  hostname_ok: boolean;
  hostname_error?: string;
}

export interface TlsObservation {
  host: string;
  port: number;
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authorization_error?: string;
  cert?: CertInfo;
}

export interface TlsOptions {
  family: 4 | 6;
  timeoutMs?: number;
  servername?: string;
  minVersion?: SecureVersion;
  maxVersion?: SecureVersion;
  ciphers?: string;
  now?: Date;
  /** Overrides DNS resolution; ScopedNet pins it to the addresses the scope guard validated. */
  lookup?: LookupFunction;
}

/** Our own client could not offer what was asked: the server's policy was never observed. */
const CLIENT_SIDE = new Set(['ERR_SSL_NO_PROTOCOLS_AVAILABLE', 'ERR_SSL_NO_CIPHERS_AVAILABLE', 'ERR_SSL_NO_CIPHER_MATCH']);
/** Network failures: nothing about TLS was observed. */
const NETWORK = new Set(['TIMEOUT', 'CONNECT_TIMEOUT', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'DNS_FAILED']);

/** True when an error code means the server refused the offered protocol or ciphers. */
export function isHandshakeRejection(code: string): boolean {
  if (CLIENT_SIDE.has(code) || NETWORK.has(code)) return false;
  return code.startsWith('ERR_SSL_') || code === 'ECONNRESET' || code === 'EPIPE';
}

function formatName(name: unknown): string {
  if (!name || typeof name !== 'object') return '';
  return Object.entries(name as Record<string, unknown>)
    .map(([k, v]) => `${k}=${String(v)}`)
    .join(', ');
}

function certInfo(peer: PeerCertificate | undefined, identityName: string, now: Date): CertInfo | undefined {
  if (!peer || Object.keys(peer).length === 0) return undefined;
  const identityError = tls.checkServerIdentity(identityName, peer);
  return {
    subject: formatName(peer.subject),
    issuer: formatName(peer.issuer),
    valid_from: peer.valid_from,
    valid_to: peer.valid_to,
    ...(peer.subjectaltname ? { subjectaltname: peer.subjectaltname } : {}),
    days_remaining: Math.floor((Date.parse(peer.valid_to) - now.getTime()) / 86_400_000),
    hostname_ok: identityError === undefined,
    ...(identityError ? { hostname_error: identityError.message } : {}),
  };
}

export function tlsHandshake(host: string, port: number, opts: TlsOptions): Promise<TlsObservation> {
  const bare = stripBrackets(host);
  const servername = opts.servername ?? (isIP(bare) ? undefined : bare);
  const timeoutMs = opts.timeoutMs ?? 10_000;
  // `family` is passed through to net.connect; @types/node's tls.ConnectionOptions does not declare it.
  const options: tls.ConnectionOptions & { family: 4 | 6 } = {
    host: bare,
    port,
    family: opts.family,
    rejectUnauthorized: false,
    ...(opts.lookup ? { lookup: opts.lookup } : {}),
    ...(servername ? { servername } : {}),
    ...(opts.minVersion ? { minVersion: opts.minVersion } : {}),
    ...(opts.maxVersion ? { maxVersion: opts.maxVersion } : {}),
    ...(opts.ciphers ? { ciphers: opts.ciphers } : {}),
  };

  return new Promise((resolve, reject) => {
    const socket = tls.connect(options);
    const timer = setTimeout(
      () => socket.destroy(new NetError('TIMEOUT', `TLS handshake with ${bare}:${port} did not finish within ${timeoutMs}ms`)),
      timeoutMs,
    );
    socket.once('secureConnect', () => {
      clearTimeout(timer);
      const authError = socket.authorizationError;
      const cert = certInfo(socket.getPeerCertificate(), servername ?? bare, opts.now ?? new Date());
      resolve({
        host: bare,
        port,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? null,
        authorized: socket.authorized,
        ...(authError ? { authorization_error: String(authError) } : {}),
        ...(cert ? { cert } : {}),
      });
      socket.end();
    });
    socket.once('error', (e) => {
      clearTimeout(timer);
      reject(toNetError(e));
    });
  });
}
