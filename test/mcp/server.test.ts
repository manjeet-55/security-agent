import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { main } from '../../src/cli.js';
import { FindingsStore } from '../../src/findings/store.js';
import { SnapshotStore } from '../../src/host/store.js';
import { projectFile } from '../../src/project/schema.js';
import { fixtureEnvelope, fixtureSnapshot } from '../helpers/snapshots.js';
import { connectMcp } from '../helpers/mcp.js';
import { makeProject } from '../helpers/project.js';
import { fixtureRecord } from '../report/fixture.js';
import { vi } from 'vitest';

const NOW = new Date('2026-10-28T12:00:00.000Z');

describe('secagent MCP server', () => {
  it('tells the client how to use it: scan first, trust only the scan, unverifiable is unknown, no fix claims without a new scan, no secrets', async () => {
    const dir = await makeProject();
    const { client } = await connectMcp({ projectDir: dir, now: () => NOW });
    const text = client.getInstructions() ?? '';
    expect(text).toContain('run_scan');
    expect(text).toMatch(/unverifiable.*unknown/i);
    expect(text).toMatch(/new scan/i);
    expect(text).toMatch(/secret/i);
    expect(client.getServerVersion()?.name).toBe('secagent');
  });

  describe('project_info', () => {
    it('describes the project, what can be scanned, and that nothing has been scanned yet', async () => {
      const dir = await makeProject();
      const mcp = await connectMcp({ projectDir: dir, now: () => NOW });
      const r = await mcp.call('project_info');
      expect(r.isError).toBe(false);
      expect(r.json).toMatchObject({
        name: 'test',
        network: { scan_label: 'test-net' },
        targets: [{ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' }],
        hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod', snapshot: null }],
        code: { enabled: true, history: true },
        groups: ['code', 'web', 'host'],
        last_scan: null,
      });
    });

    it('offers only the groups that have something to scan', async () => {
      const dir = await makeProject({ targets: [], hosts: [] });
      const mcp = await connectMcp({ projectDir: dir });
      expect((await mcp.call('project_info')).json.groups).toEqual(['code']);
    });

    it('reports how old each server snapshot is', async () => {
      const dir = await makeProject();
      const snap = fixtureSnapshot('ubuntu-24-04');
      const now = new Date(Date.parse(snap.collected_at) + 2 * 86_400_000);
      await new SnapshotStore(dir, () => now).add('web-1', JSON.stringify(fixtureEnvelope('ubuntu-24-04')));
      const mcp = await connectMcp({ projectDir: dir, now: () => now });
      const host = (await mcp.call('project_info')).json.hosts[0];
      expect(host.snapshot).toMatchObject({ collected_at: snap.collected_at, state: 'fresh' });
      expect(host.snapshot.age_days).toBeCloseTo(2, 1);
    });

    it('summarises the last scan', async () => {
      const dir = await makeProject();
      await new FindingsStore(dir).write(fixtureRecord({ trigger: 'mcp', groups_run: ['code'] }));
      const mcp = await connectMcp({ projectDir: dir, now: () => NOW });
      expect((await mcp.call('project_info')).json.last_scan).toEqual({
        scanned_at: '2026-10-28T10:00:00.000Z',
        trigger: 'mcp',
        groups_run: ['code'],
        open: 2,
        unverifiable: 1,
        results: 7,
      });
    });

    it('turns a broken project.yaml into an error result, not a crash', async () => {
      const dir = await makeProject();
      await writeFile(projectFile(dir), 'version: 1\nname: x\ntargets: [{id: Bad Id}]\n');
      const mcp = await connectMcp({ projectDir: dir });
      const r = await mcp.call('project_info');
      expect(r.isError).toBe(true);
      expect(r.text).toContain('project.yaml is invalid');
    });

    it('is read-only', async () => {
      const dir = await makeProject();
      const mcp = await connectMcp({ projectDir: dir });
      const tool = (await mcp.client.listTools()).tools.find((t) => t.name === 'project_info');
      expect(tool?.annotations?.readOnlyHint).toBe(true);
      expect(path.basename(projectFile(dir))).toBe('project.yaml');
    });
  });

  it('exposes no tool that changes project.yaml', async () => {
    const dir = await makeProject();
    const mcp = await connectMcp({ projectDir: dir });
    const names = await mcp.tools();
    expect(names.filter((n) => /write|set|add|edit|update|init|config|target|host_add/i.test(n))).toEqual([]);
  });
});

describe('secagent mcp command', () => {
  it('rejects unknown flags and a project that is not set up, before starting', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['mcp', '--bogus'])).toBe(1);
    const empty = await makeProject();
    await writeFile(projectFile(empty), 'not: [valid');
    expect(await main(['mcp', '--dir', empty])).toBe(1);
    expect(error).toHaveBeenCalled();
    error.mockRestore();
  });

  it('is listed in the usage', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    await main(['help']);
    expect(log.mock.calls.join('\n')).toContain('mcp');
    log.mockRestore();
  });
});
