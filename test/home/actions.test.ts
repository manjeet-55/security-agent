import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { main } from '../../src/cli.js';
import {
  acceptedRisks,
  addCollectorOutput,
  checkCveClaim,
  checkSetup,
  connectAi,
  exportChecklist,
  openReport,
  showFixes,
  showGuides,
  suggestedAreas,
} from '../../src/home/actions.js';
import { checklistFile } from '../../src/home/status.js';
import { SnapshotStore } from '../../src/host/store.js';
import { initProject } from '../../src/project/init.js';
import { loadProject } from '../../src/project/schema.js';
import { scanNoAi } from '../../src/scan/no-ai.js';
import { createStyle } from '../../src/ui/style.js';
import type { WizardDeps } from '../../src/wizard/steps.js';
import { fixtureAdvisories } from '../helpers/advisories.js';
import { FIXED_NOW } from '../helpers/ctx.js';
import { repoWith } from '../helpers/git.js';
import { ScriptedPrompter } from '../helpers/prompter.js';
import { FAKE } from '../helpers/secrets.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const FIXTURE = readFileSync(new URL('../fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8');
const ID = 'code-secrets-working-tree@code';

function setup(answers: unknown[], extra: Partial<WizardDeps> = {}) {
  const out = new PassThrough();
  let printed = '';
  out.on('data', (c: Buffer) => {
    printed += c.toString();
  });
  const prompter = new ScriptedPrompter(answers);
  const deps: WizardDeps = { prompter, out, style: createStyle({ isTTY: false }), now: () => FIXED_NOW, openFile: async () => true, ...extra };
  return { prompter, deps, text: () => printed };
}

/** A repo with a leaked key, set up, scanned (code) at FIXED_NOW. */
async function scanned(opts: Parameters<typeof initProject>[1] = {}): Promise<string> {
  const dir = await tempDir();
  await repoWith(dir, { 'src/app.ts': `// config\nconst id = '${FAKE.awsKeyId}';\n` });
  await initProject(dir, opts);
  await scanNoAi(dir, { only: ['code'], trigger: 'cli', now: () => FIXED_NOW });
  return dir;
}

async function withServer(): Promise<string> {
  const dir = await tempDir();
  await initProject(dir, { hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }] });
  return dir;
}

describe('home actions', () => {
  it('fix first: explains a finding (where, what, why, fix, evidence) and never shows the secret', async () => {
    const dir = await scanned();
    const { prompter, deps, text } = setup([ID, '']);
    await showFixes(dir, deps);
    prompter.done();
    const out = text();
    expect(out).toContain("Failed: No secrets in the project's source files");
    expect(out).toContain("Where     this project's code");
    expect(out).toContain('Why       ');
    expect(out).toContain('Fix       ');
    expect(out).toMatch(/Evidence  ev_/);
    expect(out).not.toContain(FAKE.awsKeyId);
  });

  it('fix first: nothing open says so and asks nothing', async () => {
    const dir = await tempDir();
    await initProject(dir);
    await scanNoAi(dir, { only: ['code'], trigger: 'cli', now: () => FIXED_NOW });
    const { prompter, deps, text } = setup([]);
    await showFixes(dir, deps);
    prompter.done();
    expect(text()).toContain('there is nothing to fix right now');
  });

  it('open the report: opens the chosen one and says where the Markdown is', async () => {
    const dir = await scanned();
    const openFile = vi.fn(async () => true);
    const { deps, text } = setup(['html'], { openFile });
    await openReport(dir, deps);
    expect(openFile).toHaveBeenCalledWith(path.join(dir, '.secagent', 'reports', 'latest.html'));
    expect(text()).toContain(path.join(dir, '.secagent', 'reports', 'latest.md'));
  });

  it('checklist areas follow the project: always secrets; websites add surface, auth, input; servers or CI add infra', async () => {
    const plain = await tempDir();
    await initProject(plain);
    expect(await suggestedAreas(plain, await loadProject(plain))).toEqual(['secrets']);
    const ci = await tempDir();
    await writeFiles(ci, { '.github/workflows/ci.yml': 'on: push\n' });
    await initProject(ci, { targets: [{ id: 'shop', url: 'https://shop.example.com', type: 'web', env: 'prod' }] });
    expect(await suggestedAreas(ci, await loadProject(ci))).toEqual(['surface', 'auth', 'input', 'secrets', 'infra']);
  });

  it('checklist hand-off writes the same file as secagent checklist for those areas, and says how to work through it', async () => {
    const dir = await scanned({ targets: [{ id: 'shop', url: 'https://shop.example.com', type: 'web', env: 'prod' }] });
    const { prompter, deps, text } = setup([undefined]);
    await exportChecklist(dir, deps);
    prompter.done();
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const viaCli = path.join(dir, 'cli-checklist.md');
    expect(await main(['checklist', '--dir', dir, '--area', 'surface', '--area', 'auth', '--area', 'input', '--area', 'secrets', '--out', viaCli])).toBe(0);
    expect(readFileSync(checklistFile(dir), 'utf8')).toBe(readFileSync(viaCli, 'utf8'));
    expect(text()).toContain('/security-review');
    expect(text()).toContain('a review, not scan results');
  });

  it('collector output: writes the script on request with the steps, then stores valid output like snapshot add', async () => {
    const dir = await withServer();
    await writeFiles(dir, { 'web-1.json': FIXTURE });
    const first = setup([undefined, true, '']);
    await addCollectorOutput(dir, first.deps);
    first.prompter.done();
    expect(first.prompter.notes.join('\n')).toContain('sudo sh collector.sh > web-1.json');
    expect(existsSync(path.join(dir, '.secagent', 'hosts', 'web-1', 'collector.sh'))).toBe(true);
    expect(first.text()).toContain('Nothing stored');
    const second = setup([undefined, false, 'web-1.json']);
    await addCollectorOutput(dir, second.deps, 'web-1');
    second.prompter.done();
    expect(second.text()).toContain("Stored web-1's collector output");
    expect((await new SnapshotStore(dir, () => FIXED_NOW).latest('web-1'))?.snapshot.os.codename).toBe('noble');
  });

  it('CVE claim: the same verdict as secagent verify; re-asks a malformed id', async () => {
    const dir = await withServer();
    await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', FIXTURE);
    const { prompter, deps, text } = setup([undefined, 'not-a-cve', 'CVE-2024-6387', ''], { advisories: fixtureAdvisories(await tempDir()) });
    await checkCveClaim(dir, deps);
    prompter.done();
    expect(prompter.rejected).toHaveLength(1);
    expect(text()).toContain('CVE-2024-6387 on web-1: fixed_in_installed');
  });

  it('accepted risks: none yet, then accepting one returns true and lists it the next time', async () => {
    const dir = await scanned();
    const first = setup(['accept', ID, 'Priya', 'rotating the key next sprint', '2026-12-15']);
    expect(await acceptedRisks(dir, first.deps)).toBe(true);
    first.prompter.done();
    expect(first.text()).toContain('No accepted risks right now.');
    const second = setup(['back']);
    expect(await acceptedRisks(dir, second.deps)).toBe(false);
    expect(second.text()).toContain(`${ID}  Priya: "rotating the key next sprint"  until 2026-12-15 (48 day(s) left)`);
  });

  it('connect an AI assistant prints the mcp setup command and what to ask', async () => {
    const dir = await withServer();
    const { deps, text } = setup([]);
    connectAi(dir, deps);
    expect(text()).toContain('claude mcp add secagent --');
    expect(text()).toContain('/security-review');
  });

  it('check this machine prints what secagent doctor prints', async () => {
    const dir = await withServer();
    const { deps, text } = setup([], { fetchImpl: (async () => new Response('{}', { status: 200 })) as typeof fetch });
    await checkSetup(dir, deps);
    expect(text()).toContain('✓ Node');
    expect(text()).toContain('No collector snapshot for server web-1');
  });

  it('guides: prints the chosen one until Back', async () => {
    const { prompter, deps, text } = setup(['servers', 'safety', '']);
    await showGuides(deps);
    prompter.done();
    expect(text()).toContain('Checking a server');
    expect(text()).toContain('What secagent touches');
  });
});
