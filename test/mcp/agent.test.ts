import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { initProject } from '../../src/project/init.js';
import { repoWith } from '../helpers/git.js';
import { connectMcp } from '../helpers/mcp.js';
import { FAKE } from '../helpers/secrets.js';
import { tempDir } from '../helpers/tmp.js';

let tick = 0;
/** A clock that moves a minute per call, so two scans have different times. */
const NOW = () => new Date(Date.parse('2026-10-28T10:00:00.000Z') + 60_000 * tick++);

describe('agent tools', () => {
  it('serve the playbook as a tool and a prompt, and put an AI summary in the report, labelled as unverified', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'src/app.ts': `const id = '${FAKE.awsKeyId}';\n` });
    await initProject(dir, { name: 'shop', scanLabel: 'office' });
    const mcp = await connectMcp({ projectDir: dir, now: NOW });

    expect((await mcp.call('get_playbook')).text).toContain('# secagent playbook');
    const prompt = await mcp.client.getPrompt({ name: 'security_review' });
    expect(JSON.stringify(prompt.messages)).toContain('Start with step 1');

    expect((await mcp.call('report_summary', { summary: 'x'.repeat(50) })).text).toContain('No scan yet');
    await mcp.call('run_scan', { groups: ['code'] });
    const r = await mcp.call('report_summary', {
      summary: 'One hard-coded cloud key was found in src/app.ts and is also in the git history; rotate it first.',
      proposals: ['Add a pre-commit secret scan.'],
    });
    expect(r.isError).toBe(false);
    const reports = path.join(dir, '.secagent', 'reports');
    const md = readFileSync(path.join(reports, 'latest.md'), 'utf8');
    expect(md).toContain('## Summary');
    expect(md).toContain('Written by an AI assistant');
    expect(md).toContain('### Proposed (not findings)');
    expect(readFileSync(path.join(reports, 'latest.html'), 'utf8')).toContain('Add a pre-commit secret scan.');

    // a new scan does not carry an old scan's summary
    await mcp.call('run_scan', { groups: ['code'] });
    expect(readFileSync(path.join(reports, 'latest.md'), 'utf8')).not.toContain('## Summary');
  });
});
