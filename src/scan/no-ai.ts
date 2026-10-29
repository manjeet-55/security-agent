import { createAdvisories } from '../advisories/index.js';
import type { Advisories } from '../advisories/types.js';
import { loadCheckInstances } from '../checks/catalog.js';
import type { AnyCheckType } from '../checks/check-type.js';
import type { CheckContext } from '../checks/context.js';
import { CHECK_TYPES } from '../checks/registry.js';
import { runChecks } from '../checks/runner.js';
import { EvidenceStore } from '../evidence/store.js';
import { diffScans } from '../findings/diff.js';
import { resultsToFindings } from '../findings/from-results.js';
import type { ScanRecord } from '../findings/schema.js';
import { FindingsStore } from '../findings/store.js';
import { SnapshotStore, type SnapshotReader } from '../host/store.js';
import { ScopedNet, type NetClient } from '../net/scoped.js';
import { GLOBAL_CHECKS_DIR } from '../paths.js';
import { loadProject } from '../project/schema.js';
import { Scope } from '../project/scope.js';
import type { CheckResult, SubjectKind } from '../types.js';

/** What a scan can be limited to: the project directory (code), the web/api targets, or the hosts. */
export const SCAN_GROUPS = ['code', 'web', 'host'] as const;
export type ScanGroup = (typeof SCAN_GROUPS)[number];

/** Subject kinds that belong to each group; a check belongs to a group when it applies to any of them. */
const GROUP_KINDS: Record<ScanGroup, readonly SubjectKind[]> = { code: ['code'], web: ['web', 'api'], host: ['host'] };

export interface ScanDeps {
  /** Defaults to a ScopedNet over project.yaml; tests may inject a fake. */
  net?: NetClient;
  now?: () => Date;
  checksDir?: string;
  types?: ReadonlyMap<string, AnyCheckType>;
  /** Defaults to the project's .secagent/hosts store. */
  snapshots?: SnapshotReader;
  /** Defaults to live OSV/Ubuntu/KEV clients with the user cache. */
  advisories?: Advisories;
  /** Run only these groups. Results and findings of the other groups are carried over from the previous scan unchanged. */
  only?: readonly ScanGroup[];
}

/** Runs every applicable check on every listed target and host, with no AI involvement. */
export async function scanNoAi(projectDir: string, deps: ScanDeps = {}): Promise<ScanRecord> {
  const project = await loadProject(projectDir);
  const now = deps.now ?? (() => new Date());
  const types = deps.types ?? CHECK_TYPES;
  const instances = await loadCheckInstances(deps.checksDir ?? GLOBAL_CHECKS_DIR, types);
  const ctx: CheckContext = {
    project,
    net: deps.net ?? new ScopedNet(new Scope(project), project.network.ip_family),
    evidence: new EvidenceStore(projectDir, project.network.scan_label, now),
    now,
    snapshots: deps.snapshots ?? new SnapshotStore(projectDir),
    advisories: deps.advisories ?? createAdvisories({ now }),
    memo: new Map(),
  };

  const groups = new Set<ScanGroup>(deps.only && deps.only.length > 0 ? deps.only : SCAN_GROUPS);
  const results: CheckResult[] = [];
  if (groups.has('web')) {
    for (const target of project.targets) results.push(...(await runChecks(ctx, { kind: 'target', target }, instances, types)));
  }
  if (groups.has('host')) {
    for (const host of project.hosts) results.push(...(await runChecks(ctx, { kind: 'host', host }, instances, types)));
  }
  if (groups.has('code') && project.code.enabled) results.push(...(await runChecks(ctx, { kind: 'code', dir: projectDir }, instances, types)));

  const store = new FindingsStore(projectDir);
  const previous = await store.latest();
  const scannedAt = now();
  const byId = new Map(instances.map((i) => [i.id, i] as const));
  const findings = resultsToFindings(results, byId, previous, project.stack, scannedAt);

  // A partial scan says nothing about the groups it skipped: they stay as the last scan left them.
  const ranKinds = new Set<SubjectKind>([...groups].flatMap((g) => GROUP_KINDS[g]));
  const skipped = (checkId: string): boolean => !byId.get(checkId)?.applies_to.some((k) => ranKinds.has(k));
  const keptResults = groups.size === SCAN_GROUPS.length ? [] : (previous?.results ?? []).filter((r) => skipped(r.check_id));
  const keptFindings = groups.size === SCAN_GROUPS.length ? [] : (previous?.findings ?? []).filter((f) => skipped(f.check_id));
  const allResults = [...keptResults, ...results];
  const allFindings = [...keptFindings, ...findings];
  const record: ScanRecord = {
    schema: 1,
    scanned_at: scannedAt.toISOString(),
    scan_label: project.network.scan_label,
    mode: 'no-ai',
    results: allResults,
    findings: allFindings,
    diff: diffScans(previous, { results: allResults, findings: allFindings }),
  };
  await store.write(record);
  return record;
}
