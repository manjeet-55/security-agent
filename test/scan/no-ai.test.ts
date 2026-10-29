import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parse, stringify } from 'yaml';
import { describe, expect, it } from 'vitest';
import { loadCheckInstances } from '../../src/checks/catalog.js';
import { CHECK_TYPES } from '../../src/checks/registry.js';
import { NetError } from '../../src/net/errors.js';
import type { NetClient } from '../../src/net/scoped.js';
import { GLOBAL_CHECKS_DIR } from '../../src/paths.js';
import { initProject } from '../../src/project/init.js';
import { projectFile } from '../../src/project/schema.js';
import { scanNoAi } from '../../src/scan/no-ai.js';
import { FIXED_NOW, fakeObs } from '../helpers/ctx.js';
import { commitAll, repoWith } from '../helpers/git.js';
import { FAKE } from '../helpers/secrets.js';
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
    const expected = (['web', 'host', 'code'] as const).reduce((n, kind) => n + instances.filter((i) => i.applies_to.includes(kind)).length, 0);
    expect(record.results).toHaveLength(expected);
    expect(record.results.filter((r) => r.outcome === 'error')).toEqual([]);
  });

  describe('code checks', () => {
    const T1 = () => new Date('2026-10-28T10:00:00.000Z');
    const T2 = () => new Date('2026-10-28T10:05:00.000Z');

    /** A repository whose app.ts leaks a key on line 2, whose history also holds it, and which tracks a .env. */
    async function leakyProject(extra: Parameters<typeof initProject>[1] = {}): Promise<string> {
      const dir = await tempDir();
      await repoWith(dir, { 'src/app.ts': `// config\nconst id = '${FAKE.awsKeyId}';\n`, '.env': 'A=1\n' });
      await initProject(dir, { scanLabel: 'test-net', ...extra });
      return dir;
    }

    async function setCode(dir: string, code: Record<string, unknown>): Promise<void> {
      const file = projectFile(dir);
      await writeFile(file, stringify({ ...parse(await readFile(file, 'utf8')), code }), 'utf8');
    }

    const NET_THAT_MUST_NOT_RUN: NetClient = {
      http: async () => {
        throw new Error('the network was used');
      },
      tls: async () => {
        throw new Error('the network was used');
      },
      tcp: async () => {
        throw new Error('the network was used');
      },
    };

    it('runs the four code checks in a plain scan, naming file and line, with no targets or hosts needed', async () => {
      const dir = await leakyProject();
      const record = await scanNoAi(dir, { net: NET_THAT_MUST_NOT_RUN, now: T1 });
      expect(record.results.map((r) => r.check_id).sort()).toEqual([
        'code-env-files-tracked',
        'code-env-not-ignored',
        'code-secrets-history',
        'code-secrets-working-tree',
      ]);
      expect(record.results.every((r) => r.target === 'code')).toBe(true);
      const byId = new Map(record.findings.map((f) => [f.id, f] as const));
      expect([...byId.keys()].sort()).toEqual(['code-env-files-tracked@code', 'code-secrets-history@code', 'code-secrets-working-tree@code']);
      expect(byId.get('code-secrets-working-tree@code')).toMatchObject({ status: 'open', severity: 'high' });
      expect(byId.get('code-secrets-working-tree@code')?.reasoning).toContain('src/app.ts:2 aws-access-key-id');
      expect(byId.get('code-env-files-tracked@code')?.reasoning).toContain('.env');
      expect(byId.get('code-secrets-history@code')?.fix?.how).toContain('Rotate');
    });

    it('skips the code checks when code.enabled is false', async () => {
      const dir = await leakyProject();
      await setCode(dir, { enabled: false });
      const record = await scanNoAi(dir, { net: NET_THAT_MUST_NOT_RUN, now: T1 });
      expect(record.results).toEqual([]);
    });

    it('--only code runs the code checks and nothing else, not even a request to the network', async () => {
      const dir = await leakyProject({
        targets: [{ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' }],
        hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }],
      });
      const record = await scanNoAi(dir, { net: NET_THAT_MUST_NOT_RUN, now: T1, only: ['code'] });
      expect(new Set(record.results.map((r) => r.target))).toEqual(new Set(['code']));
      expect(record.results).toHaveLength(4);
    });

    it('--only web runs the targets, --only host the hosts, and neither runs the code checks', async () => {
      const dir = await leakyProject({
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
      const web = await scanNoAi(dir, { net, now: T1, only: ['web'] });
      expect(new Set(web.results.map((r) => r.target))).toEqual(new Set(['app']));
      expect(web.results.length).toBeGreaterThan(0);
      const host = await scanNoAi(dir, { net, now: T2, only: ['host'] });
      // the web results are the earlier scan's, carried over untouched (same evidence), not re-observed
      expect(host.results.filter((r) => r.target === 'app')).toEqual(web.results);
      expect(host.results.filter((r) => r.target === 'web-1').length).toBeGreaterThan(0);
      expect(host.results.some((r) => r.target === 'code')).toBe(false);
    });

    it('a partial scan keeps the other groups\' results and findings as they were, and diffs only what it ran', async () => {
      const dir = await leakyProject({ targets: [{ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' }] });
      const net: NetClient = {
        http: async (url) => fakeObs({ url, bodySnippet: '<html></html>' }),
        tls: async () => {
          throw new NetError('ECONNREFUSED', 'refused');
        },
        tcp: async () => 'closed',
      };
      const full = await scanNoAi(dir, { net, now: T1 });
      const webFindings = full.findings.filter((f) => f.target === 'app');
      expect(webFindings.length).toBeGreaterThan(0);

      await writeFile(`${dir}/src/app.ts`, '// config\nconst id = process.env.ID;\n');
      commitAll(dir, 'stop leaking');
      const partial = await scanNoAi(dir, { net: NET_THAT_MUST_NOT_RUN, now: T2, only: ['code'] });

      expect(partial.findings.filter((f) => f.target === 'app')).toEqual(webFindings);
      expect(partial.results.filter((r) => r.target === 'app')).toEqual(full.results.filter((r) => r.target === 'app'));
      expect(partial.diff.fixed).toEqual(['code-secrets-working-tree@code']);
      expect(partial.diff.new).toEqual([]);
      expect(partial.diff.regressed).toEqual([]);
      expect(partial.findings.find((f) => f.id === 'code-secrets-history@code')).toMatchObject({ status: 'open' });
    });

    it('a second full scan after a partial one reports nothing new for the groups the partial scan kept', async () => {
      const dir = await leakyProject({ targets: [{ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' }] });
      const net: NetClient = {
        http: async (url) => fakeObs({ url, bodySnippet: '<html></html>' }),
        tls: async () => {
          throw new NetError('ECONNREFUSED', 'refused');
        },
        tcp: async () => 'closed',
      };
      await scanNoAi(dir, { net, now: T1 });
      await scanNoAi(dir, { net: NET_THAT_MUST_NOT_RUN, now: T2, only: ['code'] });
      const again = await scanNoAi(dir, { net, now: () => new Date('2026-10-28T10:10:00.000Z') });
      expect(again.diff).toEqual({ new: [], fixed: [], regressed: [] });
    });
  });
});
