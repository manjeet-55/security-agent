import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadCheckInstances } from '../../src/checks/catalog.js';
import { CHECK_TYPES } from '../../src/checks/registry.js';
import { NetError } from '../../src/net/errors.js';
import type { NetClient } from '../../src/net/scoped.js';
import { GLOBAL_CHECKS_DIR } from '../../src/paths.js';
import { initProject } from '../../src/project/init.js';
import { scanNoAi } from '../../src/scan/no-ai.js';
import { FIXED_NOW, fakeObs } from '../helpers/ctx.js';
import { startHttps, useServers } from '../helpers/servers.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

const HSTS_CHECK = `id: hdr-hsts
type: http_header
title: HSTS enabled
severity: medium
applies_to: [web]
params:
  header: strict-transport-security
  must_exist: true
  min_max_age: 15552000
fix_hints:
  nginx: 'add_header Strict-Transport-Security "max-age=31536000" always;'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
review: approved
`;

const track = useServers();

describe('scanNoAi', () => {
  it('opens a finding with evidence, then marks it fixed when the header appears', async () => {
    let sendHsts = false;
    const s = await track(
      startHttps((_req, res) => {
        if (sendHsts) res.setHeader('strict-transport-security', 'max-age=31536000');
        res.end('ok');
      }),
    );
    const dir = await tempDir();
    const checksDir = await tempDir();
    await writeFiles(checksDir, { 'hdr-hsts.yaml': HSTS_CHECK });
    await writeFiles(dir, { 'nginx.conf': '' });
    await initProject(dir, { scanLabel: 'test-net', targets: [{ id: 'app', url: s.url, type: 'web', env: 'test' }] });

    const first = await scanNoAi(dir, { checksDir, now: () => new Date('2026-10-28T10:00:00.000Z') });
    expect(first.findings).toHaveLength(1);
    const finding = first.findings[0];
    expect(finding).toMatchObject({ id: 'hdr-hsts@app', status: 'open', severity: 'medium' });
    expect(finding?.fix?.how).toContain('[nginx]');
    expect(existsSync(path.join(dir, '.secagent', 'evidence', `${finding?.evidence[0]}.json`))).toBe(true);
    expect(first.diff.new).toEqual(['hdr-hsts@app']);

    sendHsts = true;
    const second = await scanNoAi(dir, { checksDir, now: () => new Date('2026-10-28T10:05:00.000Z') });
    expect(second.diff.fixed).toEqual(['hdr-hsts@app']);
    expect(second.findings[0]).toMatchObject({ status: 'fixed', first_seen: '2026-10-28T10:00:00.000Z' });
    expect(existsSync(path.join(dir, '.secagent', 'findings', 'latest.json'))).toBe(true);
  });

  it('runs every applicable seed check without errors (fake network)', async () => {
    const dir = await tempDir();
    await initProject(dir, {
      targets: [{ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' }],
      hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }],
    });
    const net: NetClient = {
      http: async (url) => fakeObs({ url, bodySnippet: '<html></html>' }),
      tls: async () => {
        throw new NetError('ECONNREFUSED', 'refused');
      },
      tcp: async () => 'closed',
    };
    const record = await scanNoAi(dir, { net, now: () => FIXED_NOW });
    const instances = await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES);
    const expected = instances.filter((i) => i.applies_to.includes('web')).length + instances.filter((i) => i.applies_to.includes('host')).length;
    expect(record.results).toHaveLength(expected);
    expect(record.results.filter((r) => r.outcome === 'error')).toEqual([]);
  });
});
