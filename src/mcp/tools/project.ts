import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { FindingsStore } from '../../findings/store.js';
import { snapshotFreshness, SnapshotStore } from '../../host/store.js';
import { loadProject } from '../../project/schema.js';
import { guarded, jsonResult } from '../result.js';
import type { ServerState } from '../state.js';

async function hostSnapshot(store: SnapshotStore, name: string, now: Date): Promise<unknown> {
  try {
    const stored = await store.latest(name);
    if (!stored) return null;
    const { state, ageDays } = snapshotFreshness(stored.snapshot.collected_at, now);
    return { collected_at: stored.snapshot.collected_at, age_days: Math.round(ageDays * 10) / 10, state };
  } catch (e) {
    return { error: e instanceof Error ? e.message : String(e) };
  }
}

export async function projectInfo(state: ServerState): Promise<unknown> {
  const project = await loadProject(state.dir);
  const now = state.now();
  const snapshots = new SnapshotStore(state.dir, () => now);
  const last = await new FindingsStore(state.dir).latest();
  return {
    name: project.name,
    stack: project.stack,
    network: project.network,
    targets: project.targets.map((t) => ({ id: t.id, url: t.url, type: t.type, env: t.env })),
    hosts: await Promise.all(project.hosts.map(async (h) => ({ name: h.name, address: h.address, env: h.env, snapshot: await hostSnapshot(snapshots, h.name, now) }))),
    code: project.code,
    groups: [...(project.code.enabled ? ['code'] : []), ...(project.targets.length > 0 ? ['web'] : []), ...(project.hosts.length > 0 ? ['host'] : [])],
    last_scan: last
      ? {
          scanned_at: last.scanned_at,
          ...(last.trigger ? { trigger: last.trigger } : {}),
          ...(last.groups_run ? { groups_run: last.groups_run } : {}),
          open: last.findings.filter((f) => f.status === 'open').length,
          unverifiable: last.findings.filter((f) => f.status === 'unverifiable').length,
          results: last.results.length,
        }
      : null,
  };
}

export function registerProjectTools(server: McpServer, state: ServerState): void {
  server.registerTool(
    'project_info',
    {
      description:
        'The project secagent is set up for: its name and stack, the websites and servers listed in project.yaml (the only systems that can be probed), the code checks settings, how old each server snapshot is, which groups run_scan can run, and a summary of the last scan.',
      annotations: { readOnlyHint: true },
    },
    () => guarded(async () => jsonResult(await projectInfo(state))),
  );
}
