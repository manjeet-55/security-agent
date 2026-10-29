import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { PACKAGE_ROOT } from '../../paths.js';
import { loadReportInput } from '../../report/model.js';
import { writeSummary } from '../../report/summary.js';
import { writeReport } from '../../report/write.js';
import { guarded, jsonResult, textResult, ToolInputError } from '../result.js';
import type { ServerState } from '../state.js';

export const PLAYBOOK_FILE = path.join(PACKAGE_ROOT, 'agent', 'AGENTS.md');

export function registerAgentTools(server: McpServer, state: ServerState): void {
  server.registerPrompt(
    'security_review',
    { title: 'Security review of this project', description: 'Scan the project with secagent, explain what to fix first, help fix it and verify the fix, following the secagent playbook.' },
    async () => ({ messages: [{ role: 'user', content: { type: 'text', text: `${await readFile(PLAYBOOK_FILE, 'utf8')}\n\nStart with step 1.` } }] }),
  );

  server.registerTool(
    'get_playbook',
    {
      description: 'The secagent playbook: how to scan, explain, fix, verify, report and learn with these tools, and the rules that keep statements tied to evidence. Read it before a security review.',
      annotations: { readOnlyHint: true },
    },
    () => guarded(async () => textResult(await readFile(PLAYBOOK_FILE, 'utf8'))),
  );

  server.registerTool(
    'report_summary',
    {
      description:
        'Add a short plain-language summary, and optional proposals, to the report of the latest scan. The report shows it as written by an AI assistant and not verified by secagent. State only what the findings show; put recommendations beyond them in proposals. Replaces an earlier summary of the same scan.',
      inputSchema: {
        summary: z.string().min(40).max(3000).describe('What the latest scan shows, for a reader who is not a security specialist'),
        proposals: z.array(z.string().min(5).max(400)).max(10).optional().describe('Recommendations beyond the findings, each one sentence or two'),
      },
    },
    ({ summary, proposals }) =>
      guarded(async () => {
        const input = await loadReportInput(state.dir, state.opts.checksDir ? { checksDir: state.opts.checksDir } : {});
        if (!input) throw new ToolInputError('No scan yet: call run_scan first.');
        await writeSummary(state.dir, { scanned_at: input.record.scanned_at, summary, proposals: proposals ?? [], written_at: state.now().toISOString() });
        const fresh = await loadReportInput(state.dir, state.opts.checksDir ? { checksDir: state.opts.checksDir } : {});
        const { latest } = await writeReport(state.dir, fresh ?? input, { formats: ['md', 'pdf', 'html'] });
        return jsonResult({ saved: true, report: latest });
      }),
  );
}
