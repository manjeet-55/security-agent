import { z } from 'zod';
import { EVIDENCE_ID_PATTERN } from '../evidence/store.js';
import { FINDING_STATUSES, OUTCOMES, SEVERITIES } from '../types.js';

export const CheckResultSchema = z.object({
  check_id: z.string().min(1),
  target: z.string().min(1),
  title: z.string().min(1),
  outcome: z.enum(OUTCOMES),
  severity: z.enum(SEVERITIES),
  observed: z.string(),
  evidence_id: z.string().regex(EVIDENCE_ID_PATTERN),
  details: z.record(z.string(), z.unknown()).optional(),
});

export const FindingSchema = z.object({
  id: z.string().min(1),
  check_id: z.string().min(1),
  target: z.string().min(1),
  severity: z.enum(SEVERITIES),
  severity_reason: z.string().optional(),
  status: z.enum(FINDING_STATUSES),
  title: z.string().min(1),
  evidence: z
    .array(z.string().regex(EVIDENCE_ID_PATTERN, 'not an evidence id'))
    .min(1, 'a finding must cite at least one evidence id'),
  reasoning: z.string().min(1),
  fix: z.object({ where: z.string(), how: z.string(), side_effects: z.array(z.string()).default([]) }).optional(),
  refs: z.array(z.url()).default([]),
  knowledge: z.array(z.string()).default([]),
  first_seen: z.iso.datetime(),
  last_seen: z.iso.datetime(),
  verified_at: z.iso.datetime(),
});
export type Finding = z.infer<typeof FindingSchema>;

export const ScanDiffSchema = z.object({
  new: z.array(z.string()),
  fixed: z.array(z.string()),
  regressed: z.array(z.string()),
});
export type ScanDiff = z.infer<typeof ScanDiffSchema>;

export const ScanRecordSchema = z.object({
  schema: z.literal(1),
  scanned_at: z.iso.datetime(),
  scan_label: z.string(),
  mode: z.enum(['no-ai', 'agent']),
  results: z.array(CheckResultSchema),
  findings: z.array(FindingSchema),
  diff: ScanDiffSchema,
});
export type ScanRecord = z.infer<typeof ScanRecordSchema>;
