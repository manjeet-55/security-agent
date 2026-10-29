import type { CheckResult } from '../types.js';
import { resultKey } from './ids.js';
import type { Finding, ScanDiff, ScanRecord } from './schema.js';

/**
 * new: open now, and neither open nor passing in the previous scan.
 * regressed: open now, passing in the previous scan.
 * fixed: open (or an accepted risk) in the previous scan, passing now.
 */
export function diffScans(
  previous: ScanRecord | undefined,
  current: { results: readonly CheckResult[]; findings: readonly Finding[] },
): ScanDiff {
  const prevOpen = new Set((previous?.findings ?? []).filter((f) => f.status === 'open').map((f) => f.id));
  // An accepted risk was still a problem the last time: when its check passes now, it was fixed.
  const prevUnresolved = new Set((previous?.findings ?? []).filter((f) => f.status === 'open' || f.status === 'accepted_risk').map((f) => f.id));
  const prevPass = new Set((previous?.results ?? []).filter((r) => r.outcome === 'pass').map(resultKey));
  const curOpen = current.findings.filter((f) => f.status === 'open').map((f) => f.id);
  const curPass = new Set(current.results.filter((r) => r.outcome === 'pass').map(resultKey));
  return {
    new: curOpen.filter((id) => !prevOpen.has(id) && !prevPass.has(id)),
    fixed: [...prevUnresolved].filter((id) => curPass.has(id)),
    regressed: curOpen.filter((id) => prevPass.has(id)),
  };
}
