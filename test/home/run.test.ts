import { readFileSync } from 'node:fs';
import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { menuFor, renderStatus } from '../../src/home/run.js';
import { suggestNext } from '../../src/home/next.js';
import type { LastScan, ProjectStatus } from '../../src/home/status.js';
import { SnapshotStore } from '../../src/host/store.js';
import { initProject } from '../../src/project/init.js';
import { PromptCancelled } from '../../src/ui/prompt.js';
import { createStyle } from '../../src/ui/style.js';
import { runWizard, type WizardDeps } from '../../src/wizard/run.js';
import { FIXED_NOW } from '../helpers/ctx.js';
import { repoWith } from '../helpers/git.js';
import { ScriptedPrompter } from '../helpers/prompter.js';
import { FAKE } from '../helpers/secrets.js';
import { startHttps, useServers } from '../helpers/servers.js';
import { tempDir } from '../helpers/tmp.js';

const track = useServers();
const CONSENT = 'I own these systems or have written permission to test them';
const SCAN: LastScan = { at: '2026-10-28T10:00:00.000Z', ageDays: 1, verdict: { tone: 'green', text: 'No issues found' }, open: [], urgent: 0, unverifiable: 0 };

function status(over: Partial<ProjectStatus> = {}): ProjectStatus {
  return { name: 'shop', stack: ['nextjs'], git: true, lastScan: SCAN, websites: [], servers: [], unscanned: [], accepted: [], pendingLessons: 0, checklistExported: true, ...over };
}

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

describe('the home screen', () => {
  it('says where things stand and what is next', () => {
    const s = status({
      websites: [{ id: 'shop', url: 'https://shop.example.com', env: 'prod' }],
      servers: [{ name: 'web-1', address: '203.0.113.10', env: 'prod', collector: 'none' }],
    });
    const text = renderStatus(s, suggestNext(s), createStyle({ isTTY: false }));
    expect(text).toContain('secagent · shop  (nextjs, git)');
    expect(text).toContain('Last scan   yesterday · No issues found');
    expect(text).toContain('Websites    https://shop.example.com (prod)');
    expect(text).toContain('Servers     web-1 (prod) · no collector output yet');
    expect(text).toContain('Next: web-1 has no collector output yet');
  });

  it('puts the suggestion first, marks it, and shows only what applies (nine items for a code-only project)', () => {
    const s = status({ lastScan: { ...SCAN, open: [['high', 2]], urgent: 2 } });
    const menu = menuFor(s, suggestNext(s));
    expect(menu.map((c) => c.value)).toEqual(['fixes', 'scan', 'report', 'checklist', 'risks', 'ai', 'settings', 'help', 'exit']);
    expect(menu[0]?.hint).toBe('suggested · 2 open');
  });

  it('with servers, lessons and accepted risks it shows every item: twelve', () => {
    const s = status({
      lastScan: { ...SCAN, open: [['medium', 1]] },
      servers: [{ name: 'web-1', address: '203.0.113.10', env: 'prod', collector: 'fresh' }],
      accepted: [{ findingId: 'a@code', owner: 'Sam', reason: 'vendor fix pending', expires: '2026-12-31', daysLeft: 60 }],
      pendingLessons: 1,
    });
    expect(menuFor(s, suggestNext(s))).toHaveLength(12);
  });

  it('before any scan the first item is "Run the first scan" and there is nothing to fix or open', () => {
    const s = status({ lastScan: undefined });
    const menu = menuFor(s, suggestNext(s));
    expect(menu[0]).toMatchObject({ value: 'scan', label: 'Run the first scan' });
    expect(menu.map((c) => c.value)).not.toContain('report');
    expect(menu.map((c) => c.value)).not.toContain('fixes');
  });

  it('a new session opens the home screen; Scan again asks for consent once, then reuses it', async () => {
    const server = await track(startHttps((_req, res) => res.end('ok')));
    const dir = await tempDir();
    const first = setup([undefined, undefined, ['web'], server.url, true, 'web', 'dev', false, 'office', true, 'exit']);
    expect(await runWizard(dir, first.deps)).toBe(0);
    const second = setup(['scan', true, 'scan', 'exit']);
    expect(await runWizard(dir, second.deps)).toBe(0);
    second.prompter.done();
    expect(second.prompter.asked).not.toContain('Shall we start?');
    expect(second.prompter.asked.filter((m) => m === CONSENT)).toHaveLength(1);
    expect(second.prompter.asked.filter((m) => m === 'What do you want to do?')).toHaveLength(3);
  });

  it('an action that fails says why and comes back to the home screen', async () => {
    const dir = await tempDir();
    await initProject(dir, { hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }] });
    await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', readFileSync(new URL('../fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8'));
    // Five hours earlier, the only collector output is dated in the future: verify cannot use it.
    const before = () => new Date(FIXED_NOW.getTime() - 5 * 3_600_000);
    const { prompter, deps, text } = setup(['verify', undefined, 'CVE-2024-6387', '', 'exit'], { now: before });
    expect(await runWizard(dir, deps)).toBe(0);
    prompter.done();
    expect(text()).toContain('dated in the future');
    expect(prompter.asked.filter((m) => m === 'What do you want to do?')).toHaveLength(2);
  });

  it('Settings: check this machine, and change what is checked (then it scans)', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'src/app.ts': `const id = '${FAKE.awsKeyId}';\n` });
    await initProject(dir);
    const reachable = (async () => new Response('{}', { status: 200 })) as typeof fetch;
    const { prompter, deps, text } = setup(['settings', 'doctor', 'settings', 'change', undefined, ['code'], 'exit'], { fetchImpl: reachable });
    expect(await runWizard(dir, deps)).toBe(0);
    prompter.done();
    expect(text()).toContain('✓ Node');
    expect(text()).toContain("I'm running 5 checks on your code.");
    expect(text()).not.toContain(FAKE.awsKeyId);
  });

  it('Ctrl+C on the home screen exits 130', async () => {
    const dir = await tempDir();
    await initProject(dir);
    const { deps, text } = setup([new PromptCancelled()]);
    expect(await runWizard(dir, deps)).toBe(130);
    expect(text()).toContain('Cancelled');
  });
});
