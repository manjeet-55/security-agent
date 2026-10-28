import https from 'node:https';
import { describe, expect, it, vi } from 'vitest';
import { ADVISORY_HOSTS, createFetchJson } from '../../src/advisories/fetch.js';
import { startHttps, TEST_CERT, useServers } from '../helpers/servers.js';

const track = useServers();

describe('createFetchJson', () => {
  it('allows only the three advisory hosts over https', async () => {
    expect([...ADVISORY_HOSTS].sort()).toEqual(['api.osv.dev', 'ubuntu.com', 'www.cisa.gov']);
    const fetchJson = createFetchJson();
    await expect(fetchJson('https://evil.example.org/x')).rejects.toThrow(/not an allowlisted advisory source/);
    await expect(fetchJson('http://api.osv.dev/v1/query')).rejects.toThrow(/not an allowlisted advisory source/);
  });

  it('verifies TLS certificates (a self-signed server is rejected)', async () => {
    const s = await track(startHttps((_req, res) => res.end('{}')));
    const fetchJson = createFetchJson({ allowHosts: new Set(['127.0.0.1']) });
    await expect(fetchJson(`${s.url}/x`)).rejects.toMatchObject({ code: expect.stringMatching(/SELF_SIGNED|CERT/) });
  });
});

describe('createFetchJson deadlines and TLS settings', () => {
  it('requests with rejectUnauthorized: true', async () => {
    const spy = vi.spyOn(https, 'request');
    try {
      const fetchJson = createFetchJson({ allowHosts: new Set(['127.0.0.1']), timeoutMs: 500 });
      await fetchJson('https://127.0.0.1:1/x').catch(() => undefined);
      expect(spy).toHaveBeenCalledOnce();
      expect(spy.mock.calls[0]?.[1]).toMatchObject({ rejectUnauthorized: true });
    } finally {
      spy.mockRestore();
    }
  });

  it('gives up at the total deadline even when the server keeps dripping bytes', async () => {
    const agentCa = https.globalAgent.options.ca;
    https.globalAgent.options.ca = TEST_CERT;
    try {
      const s = await track(
        startHttps((_req, res) => {
          res.writeHead(200, { 'content-type': 'application/json' });
          const t = setInterval(() => res.write(' '), 20);
          res.on('close', () => clearInterval(t));
        }),
      );
      const fetchJson = createFetchJson({ allowHosts: new Set(['127.0.0.1']), timeoutMs: 1000, totalTimeoutMs: 300 });
      const started = Date.now();
      await expect(fetchJson(`${s.url}/x`)).rejects.toThrow(/did not finish answering within 300ms/);
      expect(Date.now() - started).toBeLessThan(900);
    } finally {
      https.globalAgent.options.ca = agentCa;
    }
  });
});
