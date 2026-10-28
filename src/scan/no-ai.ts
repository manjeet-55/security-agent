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
import { ScopedNet, type NetClient } from '../net/scoped.js';
import { GLOBAL_CHECKS_DIR } from '../paths.js';
import { loadProject } from '../project/schema.js';
import { Scope } from '../project/scope.js';
import type { CheckResult } from '../types.js';

export interface ScanDeps {
  /** Defaults to a ScopedNet over project.yaml; tests may inject a fake. */
  net?: NetClient;
  now?: () => Date;
  checksDir?: string;
  types?: ReadonlyMap<string, AnyCheckType>;
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
    memo: new Map(),
  };

  const results: CheckResult[] = [];
  for (const target of project.targets) results.push(...(await runChecks(ctx, { kind: 'target', target }, instances, types)));
  for (const host of project.hosts) results.push(...(await runChecks(ctx, { kind: 'host', host }, instances, types)));

  const store = new FindingsStore(projectDir);
  const previous = await store.latest();
  const scannedAt = now();
  const findings = resultsToFindings(results, new Map(instances.map((i) => [i.id, i])), previous, project.stack, scannedAt);
  const record: ScanRecord = {
    schema: 1,
    scanned_at: scannedAt.toISOString(),
    scan_label: project.network.scan_label,
    mode: 'no-ai',
    results,
    findings,
    diff: diffScans(previous, { results, findings }),
  };
  await store.write(record);
  return record;
}
