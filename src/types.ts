export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function maxSeverity(severities: readonly Severity[], fallback: Severity = 'info'): Severity {
  return severities.reduce<Severity>((max, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[max] ? s : max), fallback);
}

export const OUTCOMES = ['pass', 'fail', 'unverifiable', 'error'] as const;
export type Outcome = (typeof OUTCOMES)[number];

export const FINDING_STATUSES = [
  'open',
  'fixed',
  'false_positive',
  'not_applicable',
  'accepted_risk',
  'unverifiable',
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const SUBJECT_KINDS = ['web', 'api', 'host'] as const;
export type SubjectKind = (typeof SUBJECT_KINDS)[number];

/** One check instance run against one target or host. */
export interface CheckResult {
  check_id: string;
  /** Target id or host name. */
  target: string;
  title: string;
  outcome: Outcome;
  /** Effective severity for this result (a check may raise it above the instance default). */
  severity: Severity;
  /** One-line summary of what was observed. */
  observed: string;
  evidence_id: string;
  details?: Record<string, unknown>;
}
