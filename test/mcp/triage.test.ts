import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { initProject } from '../../src/project/init.js';
import { repoWith } from '../helpers/git.js';
import { connectMcp } from '../helpers/mcp.js';
import { FAKE } from '../helpers/secrets.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

let tick = 0;
const NOW = () => new Date(Date.parse('2026-10-28T10:00:00.000Z') + 60_000 * tick++);
const lesson = (id: string, review: 'approved' | 'pending') => `---
id: ${id}
title: Test fixtures hold sample keys
tags: [fixtures]
added_by: learn-2026-10-28
source_url: https://owasp.org/x
quote: sample keys are fine in fixtures
retrieved_at: "2026-10-28"
review: ${review}
${review === 'approved' ? 'reviewed_by: Priya\nreviewed_at: "2026-10-28"\n' : ''}---
The key in src/app.ts is the AWS documentation sample used by the tests.
`;

describe('triage_finding (trust rule)', () => {
  it('needs an approved citation; a pending lesson or none is refused; the next scan and the report apply it', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'src/app.ts': `const id = '${FAKE.awsKeyId}';\n` });
    await initProject(dir, { name: 'shop', scanLabel: 'office' });
    await writeFiles(dir, {
      '.secagent/knowledge/lessons/fixture-keys.md': lesson('fixture-keys', 'approved'),
      '.secagent/knowledge/lessons/pending-idea.md': lesson('pending-idea', 'pending'),
    });
    const mcp = await connectMcp({ projectDir: dir, now: NOW });
    await mcp.call('run_scan', { groups: ['code'] });
    const id = 'code-secrets-working-tree@code';
    const base = { finding_id: id, status: 'false_positive', reason: 'documented sample key used only by tests' };

    expect((await mcp.call('triage_finding', base)).text).toMatch(/Cite an approved lesson/);
    expect((await mcp.call('triage_finding', { ...base, knowledge: ['pending-idea'] })).text).toMatch(/pending review/);
    expect((await mcp.call('triage_finding', { ...base, evidence: ['ev_20261028T100000Z_deadbeef'] })).isError).toBe(true);
    const ok = await mcp.call('triage_finding', { ...base, knowledge: ['fixture-keys'] });
    expect(ok.isError).toBe(false);

    const scan = await mcp.call('run_scan', { groups: ['code'] });
    expect(scan.json.findings.find((f: any) => f.id === id)?.status).toBe('false_positive');
    const f = (await mcp.call('get_findings', { status: 'false_positive' })).json.findings[0];
    expect(f.triage).toMatchObject({ knowledge: ['fixture-keys'], by: 'ai-assistant (MCP)' });
    const md = readFileSync(path.join(dir, '.secagent', 'reports', 'latest.md'), 'utf8');
    expect(md).toContain('## Marked not a problem');
    expect(md).toContain('lesson fixture-keys');

    // the lesson is withdrawn: the finding opens again on the next scan
    await writeFiles(dir, { '.secagent/knowledge/lessons/fixture-keys.md': lesson('fixture-keys', 'pending') });
    const again = await mcp.call('run_scan', { groups: ['code'] });
    expect(again.json.findings.find((x: any) => x.id === id)?.status).toBe('open');
  });
});
