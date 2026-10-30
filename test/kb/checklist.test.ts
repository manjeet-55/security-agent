import { readFileSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { stringify } from 'yaml';
import { main } from '../../src/cli.js';
import { loadCheckInstances } from '../../src/checks/catalog.js';
import { CHECK_TYPES } from '../../src/checks/registry.js';
import type { ScanRecord } from '../../src/findings/schema.js';
import { loadChecklists, loadShippedChecklists, renderChecklist, selectAreas, type Checklist } from '../../src/kb/checklist.js';
import { KbError } from '../../src/kb/lesson.js';
import { GLOBAL_CHECKS_DIR } from '../../src/paths.js';
import { initProject } from '../../src/project/init.js';
import { repoWith } from '../helpers/git.js';
import { connectMcp } from '../helpers/mcp.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const RULES = { checkIds: new Set(['hdr-csp', 'cookie-flags']), sourceHosts: new Set(['owasp.org']) };

function item(id: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    id,
    title: `Title of ${id}`,
    severity: 'high',
    why: 'Why it matters.',
    look_for: ['Where to look.'],
    fail_if: 'When it fails.',
    pass_if: 'When it passes.',
    evidence: 'file:line',
    fix: 'How to fix it.',
    source_url: 'https://owasp.org/page',
    ...extra,
  };
}

async function dirWith(files: Record<string, unknown>): Promise<string> {
  const dir = await tempDir();
  await writeFiles(dir, Object.fromEntries(Object.entries(files).map(([name, body]) => [name, stringify(body)])));
  return dir;
}

describe('loadChecklists', () => {
  it('loads valid files, sorted by order then area, with defaults filled in', async () => {
    const dir = await dirWith({
      'zeta.yaml': { area: 'zeta', title: 'Zeta', order: 1, items: [item('zeta-one', { automated_by: ['hdr-csp'] })] },
      'alpha.yaml': { area: 'alpha', title: 'Alpha', items: [item('alpha-one', { applies_if: 'It has an API' })] },
    });
    const lists = await loadChecklists(dir, RULES);
    expect(lists.map((l) => l.area)).toEqual(['zeta', 'alpha']);
    expect(lists[1]?.items[0]?.automated_by).toEqual([]);
  });

  it('rejects unknown fields, duplicate ids, unknown checks, unlisted sources and a mismatched area, naming each', async () => {
    const dir = await dirWith({
      'one.yaml': {
        area: 'one',
        title: 'One',
        items: [item('dup'), item('bad-check', { automated_by: ['no-such-check'] }), item('bad-source', { source_url: 'https://example.com/x' })],
      },
      'two.yaml': { area: 'other', title: 'Two', items: [item('dup')] },
      'three.yaml': { area: 'three', title: 'Three', items: [item('extra', { severity_note: 'unknown field' })] },
    });
    const error = await loadChecklists(dir, RULES).then(
      () => undefined,
      (e: unknown) => e,
    );
    expect(error).toBeInstanceOf(KbError);
    const message = (error as Error).message;
    expect(message).toContain('automated_by names unknown check "no-such-check"');
    expect(message).toContain('example.com is not on the source allowlist');
    expect(message).toContain('two.yaml: area "other" must match the file name');
    expect(message).toContain('duplicate item id "dup"');
    expect(message).toContain('three.yaml');
  });

  it('ships checklists that load against the real check catalogue and source allowlist', async () => {
    const lists = await loadShippedChecklists(await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES));
    expect(lists.map((l) => l.area)).toEqual(['surface', 'auth', 'input', 'secrets', 'infra']);
    expect(lists.flatMap((l) => l.items).length).toBeGreaterThanOrEqual(40);
  });
});

describe('selectAreas and renderChecklist', () => {
  const lists = [
    { area: 'web', title: 'Web', order: 1, items: [item('web-csp', { automated_by: ['hdr-csp', 'cookie-flags'] })] },
    { area: 'code', title: 'Code', order: 2, items: [item('code-sql', { applies_if: 'It uses SQL', automated_by: [] })] },
  ] as unknown as Checklist[];

  it('keeps the asked areas in the asked order, and names the areas there are for an unknown one', () => {
    expect(selectAreas(lists, ['code', 'web']).map((l) => l.area)).toEqual(['code', 'web']);
    expect(selectAreas(lists, []).map((l) => l.area)).toEqual(['web', 'code']);
    expect(() => selectAreas(lists, ['nope'])).toThrow('Unknown checklist area "nope". Areas: web, code');
  });

  it('says there is no scan yet when there is no record', () => {
    const md = renderChecklist(lists);
    expect(md).toContain('# Security review checklist');
    expect(md).toContain('No scan yet');
    expect(md).toContain('**Automated:** `hdr-csp`: no scan yet; `cookie-flags`: no scan yet');
    expect(md).toContain('**Applies if:** It uses SQL');
    expect(md).toContain('| `code-sql` Title of code-sql | high | no |');
  });

  it('shows each automated check’s latest outcome per target', () => {
    const record = {
      scanned_at: '2026-10-30T07:02:14.610Z',
      results: [
        { check_id: 'hdr-csp', target: 'app', outcome: 'pass' },
        { check_id: 'hdr-csp', target: 'api', outcome: 'fail' },
      ],
    } as unknown as ScanRecord;
    const md = renderChecklist(lists, record);
    expect(md).toContain('from the scan of 2026-10-30 07:02 UTC');
    expect(md).toContain('`hdr-csp`: passed on app, failed on api; `cookie-flags`: not in the latest scan');
  });
});

describe('secagent checklist', () => {
  it('prints the asked areas, rejects an unknown one, and writes --out', async () => {
    const dir = await tempDir();
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});

    expect(await main(['checklist', '--dir', dir, '--area', 'auth'])).toBe(0);
    const printed = log.mock.calls.map((c) => c.join(' ')).join('\n');
    expect(printed).toContain('## Authentication and sessions');
    expect(printed).not.toContain('## Input handling');
    expect(printed).toContain('No scan yet');

    expect(await main(['checklist', '--dir', dir, '--area', 'nope'])).toBe(1);
    expect(error.mock.calls.join('\n')).toContain('Unknown checklist area "nope"');

    const out = path.join(dir, 'checklist.md');
    expect(await main(['checklist', '--dir', dir, '--area', 'surface,infra', '--out', out])).toBe(0);
    const written = readFileSync(out, 'utf8');
    expect(written).toContain('## Public surface and APIs');
    expect(written).toContain('## Cloud, containers and supply chain');
    expect(written).not.toContain('## Authentication and sessions');
  });
});

describe('get_checklist (MCP)', () => {
  it('returns the checklist with the latest scan outcomes, filtered by area', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'src/app.ts': 'export const ok = 1;\n' });
    await initProject(dir, { name: 'shop', scanLabel: 'office' });
    const mcp = await connectMcp({ projectDir: dir, now: () => new Date('2026-10-30T07:00:00.000Z') });

    expect((await mcp.call('get_checklist', { areas: ['secrets'] })).text).toContain('`code-secrets-working-tree`: no scan yet');
    await mcp.call('run_scan', { groups: ['code'] });
    const r = await mcp.call('get_checklist', { areas: ['secrets'] });
    expect(r.isError).toBe(false);
    expect(r.text).toContain('`code-secrets-working-tree`: passed on code');
    expect(r.text).not.toContain('## Input handling');
    expect((await mcp.call('get_checklist', { areas: ['nope'] })).isError).toBe(true);
  });
});
