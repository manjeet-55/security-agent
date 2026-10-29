import { existsSync, readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { describe, expect, it, vi } from 'vitest';
import { loadProject } from '../../src/project/schema.js';
import { PromptCancelled } from '../../src/ui/prompt.js';
import { createStyle } from '../../src/ui/style.js';
import { runWizard, type WizardDeps } from '../../src/wizard/run.js';
import { repoWith } from '../helpers/git.js';
import { ScriptedPrompter } from '../helpers/prompter.js';
import { FAKE } from '../helpers/secrets.js';
import { startHttps, useServers } from '../helpers/servers.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

const NOW = new Date('2026-10-28T10:00:00.000Z');
const track = useServers();

function setup(answers: unknown[], extra: Partial<WizardDeps> = {}) {
  const out = new PassThrough();
  let printed = '';
  out.on('data', (c: Buffer) => {
    printed += c.toString();
  });
  const prompter = new ScriptedPrompter(answers);
  const deps: WizardDeps = { prompter, out, style: createStyle({ isTTY: false }), now: () => NOW, openFile: async () => true, ...extra };
  return { prompter, deps, text: () => printed };
}

async function leakyRepo(): Promise<string> {
  const dir = await tempDir();
  await repoWith(dir, { 'src/app.ts': `// config\nconst id = '${FAKE.awsKeyId}';\n` });
  return dir;
}

function reportsDir(dir: string): string {
  return path.join(dir, '.secagent', 'reports');
}

describe('runWizard', () => {
  it('code only: saves the settings, shows progress and the verdict, and writes both reports', async () => {
    const dir = await leakyRepo();
    const { prompter, deps, text } = setup([undefined, ['code'], 'exit']);
    expect(await runWizard(dir, deps)).toBe(0);
    prompter.done();

    const out = text();
    expect(out).toContain('Code');
    expect(out).toMatch(/✗ \d+\/4 +No secrets in the project's source files/);
    expect(out).toContain('Needs attention: 2 high-priority issue(s)');
    expect(out).toContain(path.join(reportsDir(dir), 'latest.md'));
    expect(out).toContain(path.join(reportsDir(dir), 'latest.pdf'));
    expect(out).toContain('Fix first');
    expect(out).not.toContain(FAKE.awsKeyId);

    expect(existsSync(path.join(reportsDir(dir), 'latest.pdf'))).toBe(true);
    expect(readFileSync(path.join(reportsDir(dir), 'latest.md'), 'utf8')).toContain('src/app.ts:2 aws-access-key-id');
    expect((await loadProject(dir)).name).toBe(path.basename(dir));
  });

  it('a website: probes only after consent, records it, and lists the web checks', async () => {
    const server = await track(startHttps((_req, res) => res.end('ok')));
    const dir = await tempDir();
    const { prompter, deps, text } = setup([undefined, ['web'], server.url, true, 'web', 'dev', false, 'office', true, 'exit']);
    expect(await runWizard(dir, deps)).toBe(0);
    prompter.done();
    const out = text();
    expect(out).toContain('Websites and APIs');
    expect(out).toContain('HSTS');
    const record = JSON.parse(readFileSync(path.join(dir, '.secagent', 'findings', 'latest.json'), 'utf8'));
    expect(record.consent_at).toBe(NOW.toISOString());
    expect((await loadProject(dir)).targets[0]).toMatchObject({ url: server.url, env: 'dev', allow_private: true });
    expect(readFileSync(path.join(reportsDir(dir), 'latest.md'), 'utf8')).toContain('Scope confirmed by the person running the scan on 2026-10-28 10:00 UTC.');
  });

  it('declined consent probes nothing and saves nothing when the person quits', async () => {
    const server = await track(startHttps((_req, res) => res.end('ok')));
    const dir = await tempDir();
    const { prompter, deps, text } = setup([undefined, ['web'], server.url, true, 'web', 'dev', false, 'office', false, 'quit']);
    expect(await runWizard(dir, deps)).toBe(0);
    prompter.done();
    expect(text()).toContain('Nothing was saved');
    expect(existsSync(path.join(dir, '.secagent'))).toBe(false);
  });

  it('Scan again re-runs the scan with the same plan, without asking the questions again', async () => {
    const dir = await leakyRepo();
    const { prompter, deps } = setup([undefined, ['code'], 'again', 'exit']);
    expect(await runWizard(dir, deps)).toBe(0);
    prompter.done();
    expect(readdirSync(path.join(dir, '.secagent', 'findings', 'history'))).toHaveLength(1); // same scan time (injected clock): one file, rewritten
    expect(prompter.asked.filter((m) => m === 'Project name')).toHaveLength(1);
    expect(prompter.asked.filter((m) => m.startsWith('What next?'))).toHaveLength(2);
  });

  it('Open the report opens the PDF, then asks again', async () => {
    const dir = await leakyRepo();
    const openFile = vi.fn(async () => true);
    const { prompter, deps, text } = setup([undefined, ['code'], 'open', 'exit'], { openFile });
    expect(await runWizard(dir, deps)).toBe(0);
    prompter.done();
    expect(openFile).toHaveBeenCalledWith(path.join(reportsDir(dir), 'latest.pdf'));
    expect(text()).not.toContain('could not open');
  });

  it('says where the report is when it cannot open it', async () => {
    const dir = await leakyRepo();
    const { deps, text } = setup([undefined, ['code'], 'open', 'exit'], { openFile: async () => false });
    await runWizard(dir, deps);
    expect(text()).toContain(`Could not open it from here: ${path.join(reportsDir(dir), 'latest.pdf')}`);
  });

  it('Ctrl+C at a question exits 130 and leaves the folder untouched', async () => {
    const dir = await tempDir();
    const { deps, text } = setup([new PromptCancelled()]);
    expect(await runWizard(dir, deps)).toBe(130);
    expect(text()).toContain('Cancelled');
    expect(existsSync(path.join(dir, '.secagent'))).toBe(false);
  });

  it('an invalid project.yaml is reported with its message, not a stack trace', async () => {
    const dir = await tempDir();
    await writeFiles(dir, { '.secagent/project.yaml': 'version: 1\nname: x\ntargets: [{id: Bad Id}]\n' });
    const { deps, text } = setup([]);
    expect(await runWizard(dir, deps)).toBe(1);
    expect(text()).toContain('project.yaml is invalid');
    expect(text()).toContain('delete it to start over');
  });

  it('on a project that is already set up, Scan again goes straight to the scan', async () => {
    const dir = await leakyRepo();
    const first = setup([undefined, ['code'], 'exit']);
    await runWizard(dir, first.deps);
    const second = setup(['again', 'exit']);
    expect(await runWizard(dir, second.deps)).toBe(0);
    second.prompter.done();
    expect(second.text()).toContain('Needs attention');
  });
});
