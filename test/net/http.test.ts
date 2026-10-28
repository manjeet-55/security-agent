import { describe, expect, it } from 'vitest';
import { NetError } from '../../src/net/errors.js';
import { countHeaderBytes, httpRequest, parseSetCookie } from '../../src/net/http.js';
import { startHttp, startHttps, useServers } from '../helpers/servers.js';

const track = useServers();

describe('parseSetCookie', () => {
  it('keeps the name, lowercases attributes and redacts the value', () => {
    expect(parseSetCookie('sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax')).toEqual({
      name: 'sid',
      attributes: ['path=/', 'secure', 'httponly', 'samesite=lax'],
      redacted: 'sid=<redacted>; Path=/; Secure; HttpOnly; SameSite=Lax',
    });
  });

  it('redacts a nameless cookie, whose string is its value', () => {
    const cookie = parseSetCookie('s3cr3t; Path=/');
    expect(cookie).toEqual({ name: '', attributes: ['path=/'], redacted: '<redacted>; Path=/' });
    expect(JSON.stringify(cookie)).not.toContain('s3cr3t');
  });
});

describe('countHeaderBytes', () => {
  it('counts the status line, each header line and the blank line', () => {
    expect(countHeaderBytes('HTTP/1.1 200 OK', ['A', 'b'])).toBe(17 + 6 + 2);
  });
});

describe('httpRequest', () => {
  it('captures status, headers and redacted cookies without following redirects', async () => {
    const s = await track(
      startHttp((_req, res) => {
        res.setHeader('x-test', 'yes');
        res.setHeader('set-cookie', ['sid=topsecret; Secure', 'theme=dark']);
        res.writeHead(301, { location: 'https://example.com/' });
        res.end('moved');
      }),
    );
    const obs = await httpRequest(`${s.url}/`, { family: 4 });
    expect(obs.status).toBe(301);
    expect(obs.location).toBe('https://example.com/');
    expect(obs.headers['x-test']).toBe('yes');
    expect(obs.setCookies.map((c) => c.name)).toEqual(['sid', 'theme']);
    expect(JSON.stringify(obs)).not.toContain('topsecret');
    expect(obs.headerBytes).toBeGreaterThan(50);
    expect(obs.bodySnippet).toBe('moved');
  });

  it('accepts a self-signed HTTPS server (the tls check judges certificates)', async () => {
    const s = await track(startHttps((_req, res) => res.end('ok')));
    expect((await httpRequest(`${s.url}/`, { family: 4 })).status).toBe(200);
  });

  it('rejects with TIMEOUT when the server never answers', async () => {
    const s = await track(startHttp(() => {}));
    await expect(httpRequest(`${s.url}/`, { family: 4, timeoutMs: 300 })).rejects.toMatchObject({ code: 'TIMEOUT' });
  });

  it('rejects with ECONNREFUSED on a closed port', async () => {
    const s = await startHttp((_req, res) => res.end());
    await s.close();
    const err = await httpRequest(`${s.url}/`, { family: 4 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetError);
    expect((err as NetError).code).toBe('ECONNREFUSED');
  });

  it('caps how much body it reads', async () => {
    const s = await track(startHttp((_req, res) => res.end('x'.repeat(1_000_000))));
    const obs = await httpRequest(`${s.url}/`, { family: 4, maxBodyBytes: 1024 });
    expect(obs.bodyBytes).toBeGreaterThanOrEqual(1024);
    expect(obs.bodySnippet.length).toBeLessThanOrEqual(4096);
  });
});
