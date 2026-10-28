import { describe, expect, it } from 'vitest';
import { ADVISORY_HOSTS, createFetchJson } from '../../src/advisories/fetch.js';
import { startHttps, useServers } from '../helpers/servers.js';

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
