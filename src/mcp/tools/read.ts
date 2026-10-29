import { readFile } from 'node:fs/promises';
import path from 'node:path';
import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { EVIDENCE_ID_PATTERN, EvidenceStore } from '../../evidence/store.js';
import { FINDING_STATUSES, SEVERITIES } from '../../types.js';
import { projectStateDir } from '../../paths.js';
import { loadReportInput } from '../../report/model.js';
import { writeReport } from '../../report/write.js';
import { redactEvidence } from '../evidence.js';
import { guarded, jsonResult, textResult, ToolInputError } from '../result.js';
import type { ServerState } from '../state.js';
import { detailedFinding, sortFindings } from '../summary.js';

const NO_SCAN = 'No scan yet: call run_scan first.';

async function latestInput(state: ServerState) {
  const input = await loadReportInput(state.dir, state.opts.checksDir ? { checksDir: state.opts.checksDir } : {});
  if (!input) throw new ToolInputError(NO_SCAN);
  return input;
}

export function registerReadTools(server: McpServer, state: ServerState): void {
  server.registerTool(
    'get_findings',
    {
      description:
        'The findings of the last scan: severity, status (open, fixed, unverifiable), where, what was found, why it matters, the fix (stack-specific where known), a link to learn more and the evidence ids. Filter by status and/or severity. Findings with from_earlier_scan true were not re-checked by the last scan.',
      inputSchema: {
        status: z.enum(FINDING_STATUSES).optional().describe('Only findings with this status'),
        severity: z.enum(SEVERITIES).optional().describe('Only findings with this severity'),
      },
      annotations: { readOnlyHint: true },
    },
    ({ status, severity }) =>
      guarded(async () => {
        const input = await latestInput(state);
        const findings = sortFindings(input.record.findings).filter((f) => (!status || f.status === status) && (!severity || f.severity === severity));
        return jsonResult({
          scanned_at: input.record.scanned_at,
          ...(input.record.trigger ? { trigger: input.record.trigger } : {}),
          ...(input.record.groups_run ? { groups_run: input.record.groups_run } : {}),
          findings: findings.map((f) => detailedFinding(input, f)),
        });
      }),
  );

  server.registerTool(
    'get_report',
    {
      description: 'The report of the last scan as Markdown, followed by the path of the PDF version. It is the document a person reads; it never contains secret values.',
      annotations: { readOnlyHint: true },
    },
    () =>
      guarded(async () => {
        const input = await latestInput(state);
        const reports = path.join(projectStateDir(state.dir), 'reports');
        let markdown: string;
        try {
          markdown = await readFile(path.join(reports, 'latest.md'), 'utf8');
        } catch {
          await writeReport(state.dir, input, { formats: ['md', 'pdf', 'html'] });
          markdown = await readFile(path.join(reports, 'latest.md'), 'utf8');
        }
        return { content: [textResult(markdown).content[0]!, textResult(`PDF report: ${path.join(reports, 'latest.pdf')}`).content[0]!] };
      }),
  );

  server.registerTool(
    'get_evidence',
    {
      description:
        'One piece of evidence by id (ev_...), as cited by a finding: what was observed, when and from which network. Page bodies and cookie values are left out; code evidence holds only paths, lines and fingerprints.',
      inputSchema: { id: z.string().describe('An evidence id from a finding, like ev_20261028T100000Z_0a1b2c3d') },
      annotations: { readOnlyHint: true },
    },
    ({ id }) =>
      guarded(async () => {
        if (!EVIDENCE_ID_PATTERN.test(id)) throw new ToolInputError(`"${id}" is not an evidence id (expected ev_YYYYMMDDTHHMMSSZ_xxxxxxxx).`);
        try {
          return jsonResult(redactEvidence(await new EvidenceStore(state.dir, 'mcp').get(id)));
        } catch (e) {
          if ((e as NodeJS.ErrnoException).code === 'ENOENT') throw new ToolInputError(`No evidence with id ${id}.`);
          throw e;
        }
      }),
  );
}
