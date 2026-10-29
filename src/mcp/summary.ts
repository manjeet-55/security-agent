import type { Finding } from '../findings/schema.js';
import { areaOfTarget, whereOf, type Area, type ReportInput } from '../report/model.js';
import { SEVERITY_RANK, SEVERITIES, type Severity } from '../types.js';

export interface CompactFinding {
  id: string;
  severity: Severity;
  status: Finding['status'];
  title: string;
  where: string;
  area: Area;
  /** True when the last scan did not run this finding's area, so the finding is from an earlier scan. */
  from_earlier_scan: boolean;
  observed?: string;
}

export interface DetailedFinding extends CompactFinding {
  why?: string;
  fix?: { where: string; how: string; side_effects: string[] };
  learn_more?: string;
  /** The exceptions.yaml entry behind an accepted_risk, or one that expired (the finding is open again). */
  exception?: NonNullable<Finding['exception']>;
  evidence: string[];
}

const STATUS_ORDER: Record<string, number> = { open: 0, unverifiable: 1 };

/** Open first, then unverifiable, then the rest; within a status the most severe first, then by id. */
export function sortFindings(findings: readonly Finding[]): Finding[] {
  return [...findings].sort(
    (a, b) => (STATUS_ORDER[a.status] ?? 2) - (STATUS_ORDER[b.status] ?? 2) || SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id),
  );
}

export function compactFinding(input: ReportInput, f: Finding): CompactFinding {
  const area = areaOfTarget(input, f.check_id, f.target);
  const observed = input.record.results.find((r) => r.check_id === f.check_id && r.target === f.target)?.observed;
  return {
    id: f.id,
    severity: f.severity,
    status: f.status,
    title: f.title,
    where: whereOf(input.project, f.target),
    area,
    from_earlier_scan: input.record.groups_run !== undefined && !input.record.groups_run.includes(area),
    ...(observed ? { observed } : {}),
  };
}

export function detailedFinding(input: ReportInput, f: Finding): DetailedFinding {
  const instance = input.instances.get(f.check_id);
  return {
    ...compactFinding(input, f),
    ...(instance?.why ? { why: instance.why } : {}),
    ...(f.fix ? { fix: f.fix } : {}),
    ...(f.exception ? { exception: f.exception } : {}),
    ...(instance ? { learn_more: instance.source_url } : {}),
    evidence: f.evidence,
  };
}

export function countFindings(findings: readonly Finding[]): { by_status: Record<string, number>; open_by_severity: Record<string, number> } {
  const by_status: Record<string, number> = {};
  for (const f of findings) by_status[f.status] = (by_status[f.status] ?? 0) + 1;
  const open_by_severity: Record<string, number> = {};
  for (const s of SEVERITIES) {
    const n = findings.filter((f) => f.status === 'open' && f.severity === s).length;
    if (n > 0) open_by_severity[s] = n;
  }
  return { by_status, open_by_severity };
}
