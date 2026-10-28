import { describe, expect, it } from 'vitest';
import { NetError } from '../../src/net/errors.js';
import { isHandshakeRejection, LEGACY_CIPHERS, NON_AEAD_TLS12_CIPHERS, tlsHandshake } from '../../src/net/tls.js';
import { startTls, useServers } from '../helpers/servers.js';

const STRICT_CIPHERS =
  'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
const TLS10 = { minVersion: 'TLSv1', maxVersion: 'TLSv1', ciphers: LEGACY_CIPHERS } as const;

const track = useServers();

describe('tlsHandshake', () => {
  it('completes a TLS 1.0 handshake with a legacy server', async () => {
    const s = await track(startTls({ minVersion: 'TLSv1', ciphers: LEGACY_CIPHERS }));
    const obs = await tlsHandshake('127.0.0.1', s.port, { family: 4, ...TLS10 });
    expect(obs.protocol).toBe('TLSv1');
  });

  it('surfaces a modern server refusing TLS 1.0 as a handshake rejection', async () => {
    const s = await track(startTls({ minVersion: 'TLSv1.2' }));
    const err = await tlsHandshake('127.0.0.1', s.port, { family: 4, ...TLS10 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetError);
    expect(isHandshakeRejection((err as NetError).code)).toBe(true);
  });

  it('reads protocol, trust and hostname match from a default handshake', async () => {
    const s = await track(startTls({ minVersion: 'TLSv1.2' }));
    const obs = await tlsHandshake('127.0.0.1', s.port, { family: 4 });
    expect(obs.protocol).toBe('TLSv1.3');
    expect(obs.authorized).toBe(false);
    expect(obs.authorization_error).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
    expect(obs.cert?.hostname_ok).toBe(true);
    expect(obs.cert?.days_remaining).toBeGreaterThan(300);
  });

  it('flags a hostname mismatch when SNI names another host', async () => {
    const s = await track(startTls({ minVersion: 'TLSv1.2' }));
    const obs = await tlsHandshake('127.0.0.1', s.port, { family: 4, servername: 'example.com' });
    expect(obs.cert?.hostname_ok).toBe(false);
  });

  it('is refused when offering only non-AEAD TLS 1.2 ciphers to a strict server', async () => {
    const s = await track(startTls({ minVersion: 'TLSv1.2', ciphers: STRICT_CIPHERS }));
    const err = await tlsHandshake('127.0.0.1', s.port, {
      family: 4,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
      ciphers: NON_AEAD_TLS12_CIPHERS,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetError);
    expect(isHandshakeRejection((err as NetError).code)).toBe(true);
  });
});

describe('isHandshakeRejection', () => {
  it.each([
    ['ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION', true],
    ['ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE', true],
    ['ERR_SSL_UNSUPPORTED_PROTOCOL', true],
    ['ECONNRESET', true],
    ['ERR_SSL_NO_PROTOCOLS_AVAILABLE', false],
    ['TIMEOUT', false],
    ['ECONNREFUSED', false],
    ['ENOTFOUND', false],
  ])('%s → %s', (code, expected) => {
    expect(isHandshakeRejection(code)).toBe(expected);
  });
});
