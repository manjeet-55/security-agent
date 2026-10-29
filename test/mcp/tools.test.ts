import { existsSync, readFileSync, rmSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { NetError } from '../../src/net/errors.js';
import type { NetClient } from '../../src/net/scoped.js';
import { initProject } from '../../src/project/init.js';
import { projectFile, loadProject } from '../../src/project/schema.js';
import { fakeObs } from '../helpers/ctx.js';
import { connectMcp } from '../helpers/mcp.js';
import { repoWith } from '../helpers/git.js';
import { FAKE, PLANTED_LINES } from '../helpers/secrets.js';
import { tempDir } from '../helpers/tmp.js';
import { stringify, parse } from 'yaml';
import { writeFile } from 'node:fs/promises';

const NOW = () => new Date('2026-10-28T10:00:00.000Z');
const BODY_MARKER = 'BODYMARKER' + 'xyz789';

const NET: NetClient = {
  http: async (url) =>
    fakeObs({
      url,
      headers: { server: 'nginx' },
      setCookies: [{ name: 'sid', attributes: ['path=/'], redacted: 'sid=<redacted>; path=/' }],
      bodySnippet: `<html>${BODY_MARKER}</html>`,
    }),
  tls: async () => {
    throw new NetError('ECONNREFUSED', 'refused');
  },
  tcp: async () => 'closed',
};

const NET_MUST_NOT_RUN: NetClient = {
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

async function leakyProject(withWeb = false): Promise<string> {
  const dir = await tempDir();
  await repoWith(dir, { 'src/app.ts': `// config\nconst id = '${FAKE.awsKeyId}';\n`, '.env': 'A=1\n' });
  await initProject(dir, {
    name: 'shop',
    scanLabel: 'test-net',
    ...(withWeb ? { targets: [{ id: 'app', url: 'https://app.example.com', type: 'web' as const, env: 'prod' }] } : {}),
  });
  return dir;
}

describe('tools', () => {
  it('offers exactly these tools, none of which can change project.yaml', async () => {
    const mcp = await connectMcp({ projectDir: await leakyProject(), now: NOW });
    expect(await mcp.tools()).toEqual(['fetch_source', 'get_evidence', 'get_findings', 'get_playbook', 'get_report', 'kb_read', 'kb_search', 'kb_write', 'make_collector', 'probe_http', 'project_info', 'report_summary', 'run_scan', 'triage_finding', 'verify_claim']);
    const tools = (await mcp.client.listTools()).tools;
    for (const name of ['get_evidence', 'get_findings', 'get_playbook', 'get_report', 'kb_read', 'kb_search', 'project_info']) {
      expect(tools.find((t) => t.name === name)?.annotations?.readOnlyHint, name).toBe(true);
    }
    expect(tools.find((t) => t.name === 'run_scan')?.annotations?.readOnlyHint).not.toBe(true);
  });

  describe('run_scan', () => {
    it('scans the code and returns a verdict, compact findings that name file and line, and where the reports are', async () => {
      const dir = await leakyProject();
      const mcp = await connectMcp({ projectDir: dir, now: NOW, net: NET_MUST_NOT_RUN });
      const r = await mcp.call('run_scan', { groups: ['code'] });
      expect(r.isError).toBe(false);
      expect(r.json.verdict).toEqual({ tone: 'red', text: 'Needs attention: 3 high-priority issue(s)' });
      expect(r.json.groups_run).toEqual(['code']);
      const leak = r.json.findings.find((f: any) => f.id === 'code-secrets-working-tree@code');
      expect(leak).toMatchObject({ severity: 'high', status: 'open', where: "this project's code", area: 'code', from_earlier_scan: false });
      expect(leak.observed).toContain('src/app.ts:2 aws-access-key-id');
      expect(r.json.counts).toMatchObject({ by_status: { open: 3 }, open_by_severity: { high: 3 } });
      expect(r.json.report.markdown).toBe(path.join(dir, '.secagent', 'reports', 'latest.md'));
      expect(existsSync(r.json.report.pdf)).toBe(true);
      const record = JSON.parse(readFileSync(path.join(dir, '.secagent', 'findings', 'latest.json'), 'utf8'));
      expect(record.trigger).toBe('mcp');
      expect(readFileSync(r.json.report.markdown, 'utf8')).toContain('Run by an AI assistant through the MCP server');
    });

    it('runs every group when none is named', async () => {
      const dir = await leakyProject(true);
      const mcp = await connectMcp({ projectDir: dir, now: NOW, net: NET });
      const r = await mcp.call('run_scan');
      expect(r.json.groups_run).toEqual(['code', 'web', 'host']);
      expect(new Set(r.json.findings.map((f: any) => f.area))).toEqual(new Set(['code', 'web']));
    });

    it('marks what a partial scan did not re-check as coming from an earlier scan', async () => {
      const dir = await leakyProject(true);
      const mcp = await connectMcp({ projectDir: dir, now: NOW, net: NET });
      await mcp.call('run_scan', { groups: ['code'] });
      const r = await mcp.call('run_scan', { groups: ['web'] });
      expect(r.json.groups_run).toEqual(['web']);
      const byArea = (area: string) => r.json.findings.filter((f: any) => f.area === area);
      expect(byArea('code').length).toBeGreaterThan(0);
      expect(byArea('code').every((f: any) => f.from_earlier_scan === true)).toBe(true);
      expect(byArea('web').length).toBeGreaterThan(0);
      expect(byArea('web').every((f: any) => f.from_earlier_scan === false)).toBe(true);
    });

    it('refuses a second scan while one is running, and recovers afterwards', async () => {
      const dir = await leakyProject();
      const mcp = await connectMcp({ projectDir: dir, now: NOW });
      const [a, b] = await Promise.all([mcp.call('run_scan', { groups: ['code'] }), mcp.call('run_scan', { groups: ['code'] })]);
      expect([a.isError, b.isError].sort()).toEqual([false, true]);
      expect([a, b].find((x) => x.isError)?.text).toContain('already running');
      expect((await mcp.call('run_scan', { groups: ['code'] })).isError).toBe(false);
    });

    it('says so when the code checks are turned off and only they were asked for', async () => {
      const dir = await leakyProject();
      const file = projectFile(dir);
      const config = parse(readFileSync(file, 'utf8'));
      await writeFile(file, stringify({ ...config, code: { ...config.code, enabled: false } }));
      const mcp = await connectMcp({ projectDir: dir, now: NOW });
      const r = await mcp.call('run_scan', { groups: ['code'] });
      expect(r.isError).toBe(true);
      expect(r.text).toContain('code.enabled');
    });

    it('rejects a group that does not exist', async () => {
      const mcp = await connectMcp({ projectDir: await leakyProject(), now: NOW });
      expect((await mcp.call('run_scan', { groups: ['network'] })).isError).toBe(true);
    });

    it('does not change project.yaml', async () => {
      const dir = await leakyProject(true);
      const before = readFileSync(projectFile(dir), 'utf8');
      const mcp = await connectMcp({ projectDir: dir, now: NOW, net: NET });
      await mcp.call('run_scan');
      expect(readFileSync(projectFile(dir), 'utf8')).toBe(before);
      expect((await loadProject(dir)).targets).toHaveLength(1);
    });
  });

  describe('accepted risks', () => {
    it('are reported with who accepted them and until when, and are not open', async () => {
      const dir = await leakyProject();
      await writeFile(
        path.join(dir, '.secagent', 'knowledge', 'exceptions.yaml'),
        'exceptions:\n  - finding_id: code-secrets-working-tree@code\n    owner: dev-lead\n    reason: rotating the key next sprint\n    expires: "2026-12-31"\n',
      );
      const mcp = await connectMcp({ projectDir: dir, now: NOW });
      const r = await mcp.call('run_scan', { groups: ['code'] });
      expect(r.json.counts.by_status).toMatchObject({ accepted_risk: 1, open: 2 });
      const accepted = (await mcp.call('get_findings', { status: 'accepted_risk' })).json.findings;
      expect(accepted).toHaveLength(1);
      expect(accepted[0]).toMatchObject({ id: 'code-secrets-working-tree@code', exception: { owner: 'dev-lead', expires: '2026-12-31', expired: false } });
      expect(r.json.verdict.text).toContain('2 high-priority');
    });

    it('there is no tool that can accept one: only a person editing the file or running secagent accept can', async () => {
      const mcp = await connectMcp({ projectDir: await leakyProject(), now: NOW });
      expect((await mcp.tools()).filter((n) => /accept|exception/i.test(n))).toEqual([]);
    });
  });

  describe('get_findings', () => {
    it('says to scan first when there is no scan', async () => {
      const mcp = await connectMcp({ projectDir: await leakyProject(), now: NOW });
      const r = await mcp.call('get_findings');
      expect(r.isError).toBe(true);
      expect(r.text).toContain('No scan yet: call run_scan first');
    });

    it('returns each finding with what was found, why it matters, the fix and its evidence', async () => {
      const dir = await leakyProject();
      const mcp = await connectMcp({ projectDir: dir, now: NOW });
      await mcp.call('run_scan', { groups: ['code'] });
      const r = await mcp.call('get_findings');
      expect(r.json.groups_run).toEqual(['code']);
      const f = r.json.findings.find((x: any) => x.id === 'code-secrets-working-tree@code');
      expect(f.observed).toContain('src/app.ts:2');
      expect(f.why).toContain('source code');
      expect(f.fix.how).toContain('Rotate');
      expect(f.learn_more).toMatch(/^https:\/\//);
      expect(f.evidence).toHaveLength(1);
      expect(f.evidence[0]).toMatch(/^ev_\d{8}T\d{6}Z_[0-9a-f]{8}$/);
    });

    it('filters by status and severity', async () => {
      const dir = await leakyProject(true);
      const mcp = await connectMcp({ projectDir: dir, now: NOW, net: NET });
      await mcp.call('run_scan');
      const high = await mcp.call('get_findings', { severity: 'high' });
      expect(high.json.findings.length).toBeGreaterThan(0);
      expect(high.json.findings.every((f: any) => f.severity === 'high')).toBe(true);
      const unverifiable = await mcp.call('get_findings', { status: 'unverifiable' });
      expect(unverifiable.json.findings.every((f: any) => f.status === 'unverifiable')).toBe(true);
      expect((await mcp.call('get_findings', { status: 'fixed' })).json.findings).toEqual([]);
      expect((await mcp.call('get_findings', { status: 'nonsense' })).isError).toBe(true);
    });
  });

  describe('get_report', () => {
    it('says to scan first when there is no scan', async () => {
      const mcp = await connectMcp({ projectDir: await leakyProject(), now: NOW });
      expect((await mcp.call('get_report')).isError).toBe(true);
    });

    it('returns the Markdown report and the PDF path, and re-renders a report that was deleted', async () => {
      const dir = await leakyProject();
      const mcp = await connectMcp({ projectDir: dir, now: NOW });
      await mcp.call('run_scan', { groups: ['code'] });
      const first = await mcp.call('get_report');
      expect(first.isError).toBe(false);
      expect(first.text).toContain('# Security report: shop');
      expect(first.text).toContain(`PDF report: ${path.join(dir, '.secagent', 'reports', 'latest.pdf')}`);
      rmSync(path.join(dir, '.secagent', 'reports', 'latest.md'));
      expect((await mcp.call('get_report')).text).toContain('# Security report: shop');
    });
  });

  describe('get_evidence', () => {
    it('returns a record by id', async () => {
      const dir = await leakyProject();
      const mcp = await connectMcp({ projectDir: dir, now: NOW });
      await mcp.call('run_scan', { groups: ['code'] });
      const id = (await mcp.call('get_findings')).json.findings[0].evidence[0];
      const r = await mcp.call('get_evidence', { id });
      expect(r.isError).toBe(false);
      expect(r.json).toMatchObject({ id, kind: 'code', scan_label: 'test-net' });
    });

    it('refuses an id that is malformed or unknown', async () => {
      const mcp = await connectMcp({ projectDir: await leakyProject(), now: NOW });
      for (const id of ['../../etc/passwd', 'nope', 'ev_20261028T100000Z_deadbeef']) {
        const r = await mcp.call('get_evidence', { id });
        expect(r.isError, id).toBe(true);
      }
      expect((await mcp.call('get_evidence', { id: 'ev_20261028T100000Z_deadbeef' })).text).toContain('No evidence with id');
    });

    it('never hands over a page body, and keeps cookie values out', async () => {
      const dir = await leakyProject(true);
      const mcp = await connectMcp({ projectDir: dir, now: NOW, net: NET });
      await mcp.call('run_scan', { groups: ['web'] });
      const ids = [...new Set((await mcp.call('get_findings')).json.findings.flatMap((f: any) => f.evidence))] as string[];
      expect(ids.length).toBeGreaterThan(0);
      const records = await Promise.all(ids.map((id) => mcp.call('get_evidence', { id })));
      const http = records.filter((r) => r.json?.kind === 'http' && r.json.data?.bodySnippet !== undefined);
      expect(http.length).toBeGreaterThan(0);
      for (const r of records) expect(r.text).not.toContain(BODY_MARKER);
      expect(http[0]?.json.data.bodySnippet).toContain('omitted');
      expect(http[0]?.text).toContain('sid=<redacted>');
      // what is on disk is untouched
      const onDisk = readFileSync(path.join(dir, '.secagent', 'evidence', `${http[0]?.json.id}.json`), 'utf8');
      expect(onDisk).toContain(BODY_MARKER);
    });
  });

  it('never returns a secret value from anything it serves', async () => {
    const dir = await tempDir();
    await repoWith(dir, Object.fromEntries(Object.entries(PLANTED_LINES).map(([id, line]) => [`src/${id}.ts`, `${line}\n${FAKE.privateKeyBody}\n`])));
    await initProject(dir, { name: 'shop', scanLabel: 'test-net' });
    const mcp = await connectMcp({ projectDir: dir, now: NOW });
    const out: string[] = [(await mcp.call('run_scan', { groups: ['code'] })).text, (await mcp.call('project_info')).text];
    const findings = await mcp.call('get_findings');
    out.push(findings.text, (await mcp.call('get_report')).text);
    for (const id of new Set(findings.json.findings.flatMap((f: any) => f.evidence)) as Set<string>) out.push((await mcp.call('get_evidence', { id })).text);
    const everything = out.join('\n');
    expect(findings.json.findings.length).toBeGreaterThan(0);
    for (const raw of [FAKE.awsKeyId, FAKE.githubToken, FAKE.slackToken, FAKE.stripeLiveKey, FAKE.googleApiKey, FAKE.jwt, FAKE.urlPassword, FAKE.genericValue, FAKE.privateKeyBody]) {
      expect(everything).not.toContain(raw);
    }
  });
});
