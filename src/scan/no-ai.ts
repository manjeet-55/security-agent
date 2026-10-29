import { createAdvisories } from '../advisories/index.js';
import type { Advisories } from '../advisories/types.js';
import { loadCheckInstances } from '../checks/catalog.js';
import type { AnyCheckType } from '../checks/check-type.js';
import type { CheckContext, CheckSubject } from '../checks/context.js';
import { CHECK_TYPES } from '../checks/registry.js';
import { applicableInstances, runChecks } from '../checks/runner.js';
import { EvidenceStore } from '../evidence/store.js';
import { diffScans } from '../findings/diff.js';
import { resultsToFindings } from '../findings/from-results.js';
import type { ScanRecord } from '../findings/schema.js';
import { FindingsStore } from '../findings/store.js';
import { loadExceptions } from '../kb/exceptions.js';
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
  /** When the person running a guided scan confirmed they may test the systems in scope; recorded in the scan record. */
  consentAt?: Date;
  /** How the scan was started, recorded in the scan record and named in the report. */
  trigger?: 'wizard' | 'cli' | 'mcp';
  /** Called once before the first check with how many will run. */
  onPlan?: (total: number) => void;
  /** Called after each check, with the group it belongs to. */
  onResult?: (result: CheckResult, group: ScanGroup) => void;
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
  const runCode = groups.has('code') && project.code.enabled;
  const subjects: Array<{ group: ScanGroup; subject: CheckSubject }> = [
    ...(runCode ? [{ group: 'code' as const, subject: { kind: 'code' as const, dir: projectDir } }] : []),
    ...(groups.has('web') ? project.targets.map((target) => ({ group: 'web' as const, subject: { kind: 'target' as const, target } })) : []),
    ...(groups.has('host') ? project.hosts.map((host) => ({ group: 'host' as const, subject: { kind: 'host' as const, host } })) : []),
  ];
  deps.onPlan?.(subjects.reduce((n, s) => n + applicableInstances(instances, s.subject).length, 0));
  const results: CheckResult[] = [];
  for (const { group, subject } of subjects) {
    results.push(...(await runChecks(ctx, subject, instances, types, (r) => deps.onResult?.(r, group))));
  }

  const store = new FindingsStore(projectDir);
  const previous = await store.latest();
  const scannedAt = now();
  const byId = new Map(instances.map((i) => [i.id, i] as const));
  const findings = resultsToFindings(results, byId, previous, project.stack, scannedAt, await loadExceptions(projectDir));

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
    ...(deps.consentAt ? { consent_at: deps.consentAt.toISOString() } : {}),
    ...(deps.trigger ? { trigger: deps.trigger } : {}),
    groups_run: SCAN_GROUPS.filter((g) => groups.has(g) && (g !== 'code' || runCode)),
    results: allResults,
    findings: allFindings,
    diff: diffScans(previous, { results: allResults, findings: allFindings }),
  };
  await store.write(record);
  return record;
}
