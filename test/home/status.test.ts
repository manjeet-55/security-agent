import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { checklistFile, projectStatus } from '../../src/home/status.js';
import { SnapshotStore } from '../../src/host/store.js';
import { initProject } from '../../src/project/init.js';
import { scanNoAi } from '../../src/scan/no-ai.js';
import { FIXED_NOW } from '../helpers/ctx.js';
import { repoWith } from '../helpers/git.js';
import { FAKE } from '../helpers/secrets.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

const later = (days: number) => new Date(FIXED_NOW.getTime() + days * 86_400_000);
const FIXTURE = readFileSync(new URL('../fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8');

async function project(): Promise<string> {
  const dir = await tempDir();
  await repoWith(dir, { 'src/app.ts': `const id = '${FAKE.awsKeyId}';\n` });
  await initProject(dir, {
    name: 'shop',
    targets: [{ id: 'shop', url: 'https://shop.example.com', type: 'web', env: 'prod' }],
    hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }],
  });
  return dir;
}

describe('projectStatus', () => {
  it('a project never scanned: what is set up, and that nothing has run', async () => {
    const s = await projectStatus(await project(), FIXED_NOW);
    expect(s).toMatchObject({
      name: 'shop',
      git: true,
      websites: [{ id: 'shop', url: 'https://shop.example.com', env: 'prod' }],
      servers: [{ name: 'web-1', address: '203.0.113.10', env: 'prod', collector: 'none' }],
      unscanned: [],
      accepted: [],
      pendingLessons: 0,
      checklistExported: false,
    });
    expect(s.lastScan).toBeUndefined();
  });

  it('after a code-only scan: its age, verdict and open issues, and the site and server it did not reach', async () => {
    const dir = await project();
    await scanNoAi(dir, { only: ['code'], trigger: 'cli', now: () => FIXED_NOW });
    const s = await projectStatus(dir, later(10));
    expect(s.lastScan?.ageDays).toBe(10);
    expect(s.lastScan?.urgent).toBeGreaterThan(0);
    expect(s.lastScan?.verdict.text).toContain('Needs attention');
    expect(s.lastScan?.open.reduce((n, [, c]) => n + c, 0)).toBeGreaterThan(0);
    expect(s.unscanned).toEqual(['https://shop.example.com', 'web-1']);
  });

  it('collector output is fresh, then stale after 7 days', async () => {
    const dir = await project();
    await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', FIXTURE);
    expect((await projectStatus(dir, FIXED_NOW)).servers[0]?.collector).toBe('fresh');
    expect((await projectStatus(dir, later(8))).servers[0]?.collector).toBe('stale');
  });

  it('accepted risks in force, soonest first, with the days left; lapsed ones are left out', async () => {
    const dir = await project();
    await writeFiles(dir, {
      '.secagent/knowledge/exceptions.yaml': [
        'exceptions:',
        '  - { finding_id: b@code, owner: Priya, reason: rotating next sprint, expires: "2026-11-20" }',
        '  - { finding_id: a@code, owner: Sam, reason: vendor fix pending, expires: "2026-10-31" }',
        '  - { finding_id: c@code, owner: Sam, reason: an old decision, expires: "2026-10-01" }',
        '',
      ].join('\n'),
    });
    expect((await projectStatus(dir, FIXED_NOW)).accepted).toEqual([
      { findingId: 'a@code', owner: 'Sam', reason: 'vendor fix pending', expires: '2026-10-31', daysLeft: 3 },
      { findingId: 'b@code', owner: 'Priya', reason: 'rotating next sprint', expires: '2026-11-20', daysLeft: 23 },
    ]);
  });

  it('counts lessons waiting for review, and notices the exported checklist', async () => {
    const dir = await project();
    await writeFiles(dir, {
      '.secagent/knowledge/lessons/idea.md': '---\nid: idea\ntitle: A proposed lesson\nadded_by: learn-2026-10-28\nsource_url: https://owasp.org/x\nquote: some exact sentence from the page\nretrieved_at: "2026-10-28"\nreview: pending\n---\nBody of the lesson that explains what to do next time.\n',
      '.secagent/reports/checklist.md': '# checklist\n',
    });
    const s = await projectStatus(dir, FIXED_NOW);
    expect(s.pendingLessons).toBe(1);
    expect(s.checklistExported).toBe(true);
    expect(checklistFile(dir)).toBe(path.join(dir, '.secagent', 'reports', 'checklist.md'));
  });
});
