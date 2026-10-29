import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { isSeq, parse, parseDocument } from 'yaml';
import { z } from 'zod';
import { EVIDENCE_ID_PATTERN, EvidenceStore } from '../evidence/store.js';
import { KbError } from '../kb/lesson.js';
import { loadKnowledge } from '../kb/store.js';
import { projectKnowledgeDir } from '../paths.js';
import { FindingsStore } from './store.js';

/** How long an AI triage decision holds before the finding is open again and has to be looked at anew. */
export const TRIAGE_DAYS = 90;

export const TriageSchema = z.object({
  finding_id: z.string().min(1),
  status: z.enum(['false_positive', 'not_applicable']),
  reason: z.string().min(10),
  knowledge: z.array(z.string()).default([]),
  evidence: z.array(z.string()).default([]),
  by: z.string().min(1),
  at: z.string(),
  expires: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
});
export type TriageEntry = z.infer<typeof TriageSchema>;

const FileSchema = z.object({ triage: z.array(TriageSchema).nullish() });
const HEADER = '# Triage decisions an AI assistant made through the MCP server, each backed by approved knowledge or verify_claim evidence.\n';

function triageFile(projectDir: string): string {
  return path.join(projectKnowledgeDir(projectDir), 'triage.yaml');
}

export async function loadTriage(projectDir: string): Promise<TriageEntry[]> {
  let text: string;
  try {
    text = await readFile(triageFile(projectDir), 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw e;
  }
  const parsed = FileSchema.safeParse(parse(text) ?? {});
  if (!parsed.success) throw new KbError(`${triageFile(projectDir)}: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`);
  return parsed.data.triage ?? [];
}

/** The triage entry that holds for a finding today and whose cited lessons are still approved. */
export function activeTriage(list: readonly TriageEntry[], findingId: string, now: Date, approvedLessons: ReadonlySet<string>): TriageEntry | undefined {
  const today = now.toISOString().slice(0, 10);
  return list.find((t) => t.finding_id === findingId && today <= t.expires && (t.evidence.length > 0 || t.knowledge.some((k) => approvedLessons.has(k))));
}

const VERIFY_SUMMARY = /^verify_claim (CVE-\d{4}-\d{4,}): (fixed_in_installed|not_affected)$/;

export interface TriageInput {
  findingId: string;
  status: TriageEntry['status'];
  reason: string;
  knowledge?: string[];
  evidence?: string[];
}

/**
 * The trust rule (spec §5.4): a finding may be called a false positive or not applicable only by citing an approved lesson or
 * verify_claim evidence for the same host that says fixed_in_installed or not_affected. Pending knowledge never qualifies.
 */
export async function triageFinding(projectDir: string, input: TriageInput, now: Date): Promise<TriageEntry> {
  if (input.reason.trim().length < 10) throw new KbError('reason must say why, in at least 10 characters');
  const record = await new FindingsStore(projectDir).latest();
  if (!record) throw new KbError('No scan yet: call run_scan first.');
  const finding = record.findings.find((f) => f.id === input.findingId);
  if (!finding) throw new KbError(`No finding "${input.findingId}" in the latest scan.`);
  if (finding.status !== 'open') throw new KbError(`"${finding.id}" is ${finding.status}; only open findings can be triaged.`);

  const lessons = (await loadKnowledge(projectDir, [])).lessons;
  const goodKnowledge: string[] = [];
  for (const id of input.knowledge ?? []) {
    const l = lessons.find((x) => x.id === id);
    if (!l) throw new KbError(`No lesson "${id}"; use kb_search.`);
    if (l.review !== 'approved') throw new KbError(`Lesson "${id}" is pending review; pending knowledge cannot back calling a finding a false positive.`);
    goodKnowledge.push(id);
  }
  const goodEvidence: string[] = [];
  const store = new EvidenceStore(projectDir, 'triage');
  for (const id of input.evidence ?? []) {
    if (!EVIDENCE_ID_PATTERN.test(id)) throw new KbError(`"${id}" is not an evidence id`);
    const ev = await store.get(id).catch(() => undefined);
    if (!ev) throw new KbError(`No evidence ${id}`);
    if (ev.kind !== 'advisory' || !VERIFY_SUMMARY.test(ev.summary) || ev.target !== finding.target) {
      throw new KbError(`Evidence ${id} is not a verify_claim verdict of fixed_in_installed or not_affected for ${finding.target}.`);
    }
    goodEvidence.push(id);
  }
  if (goodKnowledge.length === 0 && goodEvidence.length === 0) {
    throw new KbError('Cite an approved lesson (knowledge) or verify_claim evidence (evidence) that shows this is not a problem. Without one, the finding stays open; a person can accept the risk with secagent accept.');
  }

  const expires = new Date(now.getTime() + TRIAGE_DAYS * 86_400_000).toISOString().slice(0, 10);
  const entry: TriageEntry = { finding_id: finding.id, status: input.status, reason: input.reason.trim(), knowledge: goodKnowledge, evidence: goodEvidence, by: 'ai-assistant (MCP)', at: now.toISOString(), expires };
  const file = triageFile(projectDir);
  let text = '';
  try {
    text = await readFile(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  const doc = parseDocument(text.trim() === '' ? `${HEADER}triage: []\n` : text);
  const list = doc.get('triage');
  if (isSeq(list)) {
    list.flow = false;
    list.items = list.items.filter((n) => (n as { get?: (k: string) => unknown }).get?.('finding_id') !== finding.id);
    list.add(doc.createNode(entry));
  } else {
    doc.set('triage', doc.createNode([entry]));
  }
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, doc.toString(), 'utf8');
  return entry;
}
