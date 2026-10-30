import { readFileSync } from 'node:fs';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { createDemoProject } from '../scripts/demo-setup.js';
import { startDemoServer } from '../scripts/demo-server.js';
import { initProject } from '../src/project/init.js';
import { scanNoAi } from '../src/scan/no-ai.js';
import { createStyle } from '../src/ui/style.js';
import { runWizard } from '../src/wizard/run.js';
import { git } from './helpers/git.js';
import { ScriptedPrompter } from './helpers/prompter.js';
import { FAKE } from './helpers/secrets.js';
import { tempDir } from './helpers/tmp.js';
import { NO_ADVISORIES } from './helpers/ctx.js';

const NOW = () => new Date('2026-10-28T10:00:00.000Z');
/** OSV as the demo needs it: the two old pins have advisories. No network. */
const OSV_FAKE = {
  ...NO_ADVISORIES,
  osv: {
    affected: async (_e: string, qs: ReadonlyArray<{ name: string }>) => new Set(qs.map((q) => q.name).filter((n) => n === 'lodash' || n === 'express')),
    vulnsFor: async (_e: string, q: { name: string }) => [{ id: `GHSA-demo-${q.name}` }],
    vuln: async () => null,
  },
};

describe('demo project', () => {
  it('leaks in every way the code checks look for, and holds no real secret', async () => {
    const dir = await tempDir();
    await createDemoProject(dir);
    await initProject(dir, {});
    const record = await scanNoAi(dir, { only: ['code'], now: NOW, advisories: OSV_FAKE });
    expect(record.findings.filter((f) => f.status === 'open').map((f) => f.id).sort()).toEqual([
      'code-dependencies-npm@code',
      'code-env-files-tracked@code',
      'code-env-not-ignored@code',
      'code-secrets-history@code',
      'code-secrets-working-tree@code',
    ]);
    // the history check also sees the token a later commit removed
    expect(git(dir, 'log', '--oneline').trim().split('\n')).toHaveLength(3);
    expect(git(dir, 'status', '--porcelain')).toContain('?? server.key');
    expect(readFileSync(path.join(dir, 'src', 'config.js'), 'utf8')).toContain('AKIA');
  });

  it('can be created twice in a fresh folder, and refuses a folder that already has files', async () => {
    const dir = await tempDir();
    await createDemoProject(path.join(dir, 'a'));
    await expect(createDemoProject(path.join(dir, 'a'))).rejects.toThrow('is not empty');
  });
});

describe('demo server', () => {
  it('sends no security headers, a flagless cookie and a leaked .env', async () => {
    const server = await startDemoServer(0);
    try {
      const home = await fetch(server.url);
      expect(home.status).toBe(200);
      expect(home.headers.get('strict-transport-security')).toBeNull();
      expect(home.headers.get('content-security-policy')).toBeNull();
      expect(home.headers.get('x-powered-by')).toMatch(/Express/);
      expect(home.headers.get('server')).toMatch(/\d/);
      expect(home.headers.get('set-cookie')).not.toMatch(/HttpOnly|Secure/i);
      const env = await fetch(`${server.url}/.env`);
      expect(env.status).toBe(200);
      expect(await env.text()).toMatch(/^API_KEY=/m);
      expect((await fetch(`${server.url}/definitely-not-here`)).status).toBe(404);
    } finally {
      await server.close();
    }
  });
});

describe('the demo, end to end', () => {
  it('the guided scan of the demo project and server ends in a red verdict and a report naming the site', async () => {
    const dir = await tempDir();
    await createDemoProject(dir);
    const server = await startDemoServer(0);
    try {
      const out = new PassThrough();
      let printed = '';
      out.on('data', (c: Buffer) => {
        printed += c.toString();
      });
      const prompter = new ScriptedPrompter([undefined, undefined, ['code', 'web'], server.url, true, 'web', 'dev', false, 'office', true, 'exit']);
      expect(await runWizard(dir, { prompter, out, style: createStyle({ isTTY: false }), now: NOW, openFile: async () => true, advisories: OSV_FAKE })).toBe(0);
      prompter.done();
      expect(printed).toContain('Needs attention');
      const md = readFileSync(path.join(dir, '.secagent', 'reports', 'latest.md'), 'utf8');
      expect(md).toContain(server.url);
      expect(md).toContain('Failed: HSTS enabled');
      expect(md).toContain('/.env');
      for (const raw of [FAKE.awsKeyId]) expect(printed + md).not.toContain(raw);
    } finally {
      await server.close();
    }
  });
});
