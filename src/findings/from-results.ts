import type { CheckInstance } from '../checks/catalog.js';
import type { Stack } from '../project/schema.js';
import type { CheckResult, FindingStatus } from '../types.js';
import { selectFix } from './fix.js';
import { resultKey } from './ids.js';
import type { Finding, ScanRecord } from './schema.js';

/** Deterministic (--no-ai) mapping: fail → open, unverifiable/error → unverifiable, previously open now passing → fixed. */
export function resultsToFindings(
  results: readonly CheckResult[],
  instances: ReadonlyMap<string, CheckInstance>,
  previous: ScanRecord | undefined,
  stack: Stack,
  now: Date,
): Finding[] {
  const previousById = new Map((previous?.findings ?? []).map((f) => [f.id, f] as const));
  const iso = now.toISOString();
  const findings: Finding[] = [];

  for (const r of results) {
    const id = resultKey(r);
    const prev = previousById.get(id);
    const status: FindingStatus | undefined =
      r.outcome === 'fail'
        ? 'open'
        : r.outcome === 'unverifiable' || r.outcome === 'error'
          ? 'unverifiable'
          : prev?.status === 'open'
            ? 'fixed'
            : undefined;
    if (status === undefined) continue;

    const inst = instances.get(r.check_id);
    findings.push({
      id,
      check_id: r.check_id,
      target: r.target,
      severity: r.severity,
      ...(inst && r.severity !== inst.severity
        ? { severity_reason: `Set by the ${inst.type} check from what it observed (default ${inst.severity}).` }
        : {}),
      status,
      title: r.title,
      evidence: [r.evidence_id],
      reasoning: `No AI triage (--no-ai). Check outcome: ${r.outcome}. Observed: ${r.observed}`,
      ...(inst && status === 'open' ? { fix: selectFix(inst, stack) } : {}),
      refs: inst ? [inst.source_url] : [],
      knowledge: inst ? [inst.id] : [],
      first_seen: prev?.first_seen ?? iso,
      last_seen: iso,
      verified_at: iso,
    });
  }
  return findings;
}
