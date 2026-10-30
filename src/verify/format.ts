import type { ClaimResult } from './claim.js';

/** What `secagent verify` prints for a verdict. */
export function formatClaim(r: ClaimResult): string[] {
  return [
    `${r.cve} on ${r.host}: ${r.verdict}${r.kev === true ? ' (CISA KEV: known exploited)' : ''}`,
    `  ${r.reason}`,
    ...r.packages.map(
      (p) => `  ${p.package}: installed ${p.installed ?? '-'}, distro status ${p.distro_status}${p.fixed ? `, fixed in ${p.fixed}` : ''} → ${p.verdict}`,
    ),
    ...(r.source_url ? [`  source: ${r.source_url}`] : []),
    ...(r.as_of ? [`  advisories as of ${r.as_of.slice(0, 10)}${r.stale ? ' (STALE: cached copy, source unreachable)' : ''}`] : []),
    `  evidence: ${r.evidence_id}`,
  ];
}
