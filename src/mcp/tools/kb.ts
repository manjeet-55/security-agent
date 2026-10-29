import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import { kbRead, kbSearch, loadKnowledge } from '../../kb/store.js';
import { guarded, jsonResult } from '../result.js';
import type { ServerState } from '../state.js';

export function registerKbTools(server: McpServer, state: ServerState): void {
  server.registerTool(
    'kb_search',
    {
      description:
        'Keyword search over lessons (global and this project\'s) and check instances. Optional tags must all match. Each hit says whether it is approved or pending review; pending knowledge may add a finding or raise severity but can never justify calling something safe or lowering a severity.',
      inputSchema: { query: z.string(), tags: z.array(z.string().min(1)).optional() },
      annotations: { readOnlyHint: true },
    },
    ({ query, tags }) => guarded(async () => jsonResult({ hits: kbSearch(await loadKnowledge(state.dir, await state.instances()), query, tags ?? []) })),
  );

  server.registerTool(
    'kb_read',
    {
      description:
        'One lesson or check instance by id. Special ids: "INDEX" (one line per lesson and check; read it first), "notes" (the project\'s notes.md), "exceptions" (accepted risks in exceptions.yaml).',
      inputSchema: { id: z.string().min(1) },
      annotations: { readOnlyHint: true },
    },
    ({ id }) => guarded(async () => jsonResult(await kbRead(await loadKnowledge(state.dir, await state.instances()), id, state.dir))),
  );
}
