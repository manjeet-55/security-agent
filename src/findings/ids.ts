/** Stable across scans so diffs can match findings: "<check>@<target>" or "<check>:<CVE>@<host>". */
export function findingId(checkId: string, target: string, cve?: string): string {
  return cve ? `${checkId}:${cve}@${target}` : `${checkId}@${target}`;
}

export function resultKey(r: { check_id: string; target: string }): string {
  return findingId(r.check_id, r.target);
}
