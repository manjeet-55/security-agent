import type { CheckInstance } from '../checks/catalog.js';
import type { Stack } from '../project/schema.js';
import type { CheckResult, FindingStatus } from '../types.js';
import { selectFix } from './fix.js';
import { resultKey } from './ids.js';
import type { Finding, ScanRecord } from './schema.js';

/**
 * Deterministic (--no-ai) mapping: fail → open, unverifiable/error → unverifiable, previously open now passing → fixed.
 * A finding that was open stays open (not re-verified, verified_at unchanged) when its check is unverifiable or errors.
 */
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
    const inst = instances.get(r.check_id);
    if ((r.outcome === 'unverifiable' || r.outcome === 'error') && prev?.status === 'open') {
      findings.push({
        id,
        check_id: r.check_id,
        target: r.target,
        severity: prev.severity,
        ...(prev.severity_reason ? { severity_reason: prev.severity_reason } : {}),
        status: 'open',
        title: r.title,
        evidence: [...new Set([r.evidence_id, ...prev.evidence])],
        reasoning: `Not re-verified this scan (check outcome: ${r.outcome}); the previous open status stands. Observed: ${r.observed}`,
        ...(inst ? { fix: selectFix(inst, stack) } : {}),
        refs: inst ? [inst.source_url] : [],
        knowledge: inst ? [inst.id] : [],
        first_seen: prev.first_seen,
        last_seen: prev.last_seen,
        verified_at: prev.verified_at,
      });
      continue;
    }
    const status: FindingStatus | undefined =
      r.outcome === 'fail'
        ? 'open'
        : r.outcome === 'unverifiable' || r.outcome === 'error'
          ? 'unverifiable'
          : prev?.status === 'open'
            ? 'fixed'
            : undefined;
    if (status === undefined) continue;

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
