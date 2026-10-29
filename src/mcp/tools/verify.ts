import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { createAdvisories } from '../../advisories/index.js';
import { EvidenceStore } from '../../evidence/store.js';
import { SnapshotStore } from '../../host/store.js';
import { loadProject } from '../../project/schema.js';
import { Scope } from '../../project/scope.js';
import { verifyClaim } from '../../verify/claim.js';
import { guarded, jsonResult } from '../result.js';
import type { ServerState } from '../state.js';

export function registerVerifyTools(server: McpServer, state: ServerState): void {
  server.registerTool(
    'verify_claim',
    {
      description:
        'Decide whether a third-party scanner\'s claim "CVE-X affects host H" is true, from the host\'s collector snapshot and the distro\'s own security advisories (not from version numbers alone). Verdicts: fixed_in_installed (the distro backported the fix: a false positive), not_affected, vulnerable, no_fix_available, unverifiable. Only hosts listed in project.yaml; the snapshot must be recent.',
      inputSchema: {
        host: z.string().describe('A host name from project_info'),
        cve: z.string().regex(/^CVE-\d{4}-\d{4,}$/i, 'must look like CVE-2024-6387'),
        package: z.string().optional().describe('Limit the check to this package'),
      },
      annotations: { openWorldHint: true },
    },
    ({ host, cve, package: pkg }) =>
      guarded(async () => {
        const { opts } = state;
        const project = await loadProject(state.dir);
        const now = () => state.now();
        const result = await verifyClaim(
          {
            host: new Scope(project).host(host),
            snapshots: new SnapshotStore(state.dir, now),
            advisories: opts.advisories ?? createAdvisories({ now }),
            evidence: new EvidenceStore(state.dir, project.network.scan_label, now),
            now,
          },
          { cve, ...(pkg ? { package: pkg } : {}) },
        );
        return jsonResult(result);
      }),
  );
}
