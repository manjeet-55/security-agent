import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { hasConsent, NOT_CONFIRMED } from '../../project/consent.js';
import { loadProject } from '../../project/schema.js';
import { loadReportInput, verdict } from '../../report/model.js';
import { writeReport } from '../../report/write.js';
import { scanNoAi, SCAN_GROUPS } from '../../scan/no-ai.js';
import { guarded, jsonResult, ToolInputError } from '../result.js';
import type { ServerState } from '../state.js';
import { compactFinding, countFindings, sortFindings } from '../summary.js';

export function registerScanTools(server: McpServer, state: ServerState): void {
  server.registerTool(
    'run_scan',
    {
      description:
        'Run secagent\'s deterministic checks and write the Markdown and PDF report. groups limits the run to code, web (websites and APIs) and/or host (servers); omit it to run everything project_info lists. The other groups keep their results from the last scan and are marked from_earlier_scan. Only the websites and servers in project.yaml are ever probed. One scan runs at a time.',
      inputSchema: { groups: z.array(z.enum(SCAN_GROUPS)).optional().describe('Which groups to run; default: all') },
    },
    ({ groups }) =>
      guarded(async () => {
        if (state.scanning) throw new ToolInputError('A scan is already running. Wait for it to finish, then call get_findings.');
        state.scanning = true;
        try {
          const only = groups && groups.length > 0 ? [...new Set(groups)] : undefined;
          const project = await loadProject(state.dir);
          const probes = (only ?? ['web', 'host']).some((g) => (g === 'web' && project.targets.length > 0) || (g === 'host' && project.hosts.length > 0));
          if (probes && !(await hasConsent(state.dir, project))) throw new ToolInputError(NOT_CONFIRMED);
          if (only?.length === 1 && only[0] === 'code' && !project.code.enabled) {
            throw new ToolInputError('The code checks are turned off (code.enabled is false in project.yaml), so there is nothing to scan for "code".');
          }
          const { opts } = state;
          await scanNoAi(state.dir, {
            trigger: 'mcp',
            ...(only ? { only } : {}),
            ...(opts.now ? { now: opts.now } : {}),
            ...(opts.net ? { net: opts.net } : {}),
            ...(opts.advisories ? { advisories: opts.advisories } : {}),
            ...(opts.checksDir ? { checksDir: opts.checksDir } : {}),
          });
          const input = await loadReportInput(state.dir, opts.checksDir ? { checksDir: opts.checksDir } : {});
          if (!input) throw new Error('the scan did not leave a record to report on');
          const { latest } = await writeReport(state.dir, input, { formats: ['md', 'pdf', 'html'] });
          return jsonResult({
            verdict: verdict(input.record),
            groups_run: input.record.groups_run,
            counts: countFindings(input.record.findings),
            findings: sortFindings(input.record.findings).map((f) => compactFinding(input, f)),
            diff: input.record.diff,
            report: { markdown: latest[0], pdf: latest[1], html: latest[2] },
          });
        } finally {
          state.scanning = false;
        }
      }),
  );
}
