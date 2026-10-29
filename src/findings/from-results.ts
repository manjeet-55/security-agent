import type { CheckInstance } from '../checks/catalog.js';
import { exceptionFor, type RiskException } from '../kb/exceptions.js';
import type { Stack } from '../project/schema.js';
import type { CheckResult, FindingStatus } from '../types.js';
import { selectFix } from './fix.js';
import { resultKey } from './ids.js';
import type { Finding, ScanRecord } from './schema.js';

const acceptedNote = (e: { owner: string; expires: string; reason: string }): string => `Accepted risk by ${e.owner} until ${e.expires}: ${e.reason}. `;
const expiredNote = (e: { owner: string; expires: string }): string => `An earlier exception (${e.owner}, until ${e.expires}) has expired, so this is open again. `;

/** An open finding covered by an exception becomes an accepted risk; one whose exception lapsed stays open and says so. */
function withException(f: Finding, exceptions: readonly RiskException[], now: Date): Finding {
  if (f.status !== 'open') return f;
  const found = exceptionFor(exceptions, f.id, now);
  if (!found) return f;
  const exception = { owner: found.owner, reason: found.reason, expires: found.expires, expired: found.expired };
  if (found.expired) return { ...f, exception, reasoning: `${expiredNote(found)}${f.reasoning}` };
  return { ...f, status: 'accepted_risk', exception, reasoning: `${acceptedNote(found)}${f.reasoning}` };
}

/**
 * Exceptions follow the calendar, not the checks, so findings a partial scan carries over from an earlier scan are judged again:
 * an accepted risk whose date has passed (or whose entry was removed) is open again, an open finding that an exception now
 * covers is accepted, and an entry that changed is followed. Findings in any other status are returned as they are.
 */
export function reapplyExceptions(findings: readonly Finding[], exceptions: readonly RiskException[], now: Date): Finding[] {
  return findings.map((f) => {
    if (f.status !== 'accepted_risk') return withException(f, exceptions, now);
    const prefix = f.exception ? acceptedNote(f.exception) : '';
    const { exception: _accepted, ...rest } = f;
    const reopened: Finding = { ...rest, status: 'open', reasoning: prefix && f.reasoning.startsWith(prefix) ? f.reasoning.slice(prefix.length) : f.reasoning };
    return withException(reopened, exceptions, now);
  });
}

/**
 * Deterministic (--no-ai) mapping: fail → open, unverifiable/error → unverifiable, previously open now passing → fixed.
 * A finding that was open stays open (not re-verified, verified_at unchanged) when its check is unverifiable or errors.
 * An open finding with an active exception in exceptions.yaml is an accepted risk; one that was accepted and now passes is fixed.
 */
export function resultsToFindings(
  results: readonly CheckResult[],
  instances: ReadonlyMap<string, CheckInstance>,
  previous: ScanRecord | undefined,
  stack: Stack,
  now: Date,
  exceptions: readonly RiskException[] = [],
): Finding[] {
  const previousById = new Map((previous?.findings ?? []).map((f) => [f.id, f] as const));
  const iso = now.toISOString();
  const findings: Finding[] = [];

  for (const r of results) {
    const id = resultKey(r);
    const prev = previousById.get(id);
    const inst = instances.get(r.check_id);
    if ((r.outcome === 'unverifiable' || r.outcome === 'error') && (prev?.status === 'open' || prev?.status === 'accepted_risk')) {
      findings.push(withException({
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
      }, exceptions, now));
      continue;
    }
    const status: FindingStatus | undefined =
      r.outcome === 'fail'
        ? 'open'
        : r.outcome === 'unverifiable' || r.outcome === 'error'
          ? 'unverifiable'
          : prev?.status === 'open' || prev?.status === 'accepted_risk'
            ? 'fixed'
            : undefined;
    if (status === undefined) continue;

    findings.push(withException({
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
    }, exceptions, now));
  }
  return findings;
}
