import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parseDocument, isSeq } from 'yaml';
import { FindingsStore } from '../findings/store.js';
import { projectKnowledgeDir } from '../paths.js';
import { activeException, loadExceptions, type RiskException } from './exceptions.js';
import { KbError } from './lesson.js';

export interface AcceptInput {
  findingId: string;
  owner: string;
  reason: string;
  /** Last day the acceptance holds, YYYY-MM-DD. */
  until: string;
}

const HEADER = '# Accepted risks. Each entry: finding_id, owner, reason, expires (YYYY-MM-DD).\n';
const MIN_REASON = 10;
const MAX_DAYS = 366;

function checkDate(until: string, now: Date): void {
  if (!/^\d{4}-\d{2}-\d{2}$/.test(until)) throw new KbError(`--until must be a date like 2026-12-31 (YYYY-MM-DD), not "${until}"`);
  const date = new Date(`${until}T00:00:00.000Z`);
  if (Number.isNaN(date.getTime()) || date.toISOString().slice(0, 10) !== until) throw new KbError(`--until "${until}" is not a real date`);
  const today = now.toISOString().slice(0, 10);
  if (until <= today) throw new KbError(`--until must be after today (${today}): an accepted risk needs an expiry in the future`);
  const days = (date.getTime() - new Date(`${today}T00:00:00.000Z`).getTime()) / 86_400_000;
  if (days > MAX_DAYS) throw new KbError('--until is more than one year away: accepted risks must be reviewed at least yearly');
}

/**
 * Records a person's decision to accept an open finding's risk until a date, in .secagent/knowledge/exceptions.yaml. The next scan
 * reports the finding as an accepted risk; when the date passes it is open again. Only open findings can be accepted.
 */
export async function acceptRisk(projectDir: string, input: AcceptInput, now: Date): Promise<RiskException> {
  const owner = input.owner.trim();
  const reason = input.reason.trim();
  if (owner === '') throw new KbError('--owner must name the person who accepts the risk');
  if (reason.length < MIN_REASON) throw new KbError(`--reason must say why the risk is accepted (at least ${MIN_REASON} characters)`);
  checkDate(input.until, now);

  const record = await new FindingsStore(projectDir).latest();
  if (!record) throw new KbError('No scan yet: run secagent scan --no-ai first');
  const finding = record.findings.find((f) => f.id === input.findingId);
  if (!finding) {
    const open = record.findings.filter((f) => f.status === 'open').map((f) => f.id);
    throw new KbError(`No finding "${input.findingId}" in the latest scan.${open.length > 0 ? ` Open findings: ${open.slice(0, 10).join(', ')}${open.length > 10 ? ', ...' : ''}` : ' It has no open findings.'}`);
  }
  if (finding.status !== 'open') throw new KbError(`"${finding.id}" is ${finding.status}; only open findings can be accepted.`);
  const existing = activeException(await loadExceptions(projectDir), finding.id, now);
  if (existing) throw new KbError(`"${finding.id}" is already accepted until ${existing.expires}. Edit exceptions.yaml to change that.`);

  const entry: RiskException = { finding_id: finding.id, owner, reason, expires: input.until };
  const dir = projectKnowledgeDir(projectDir);
  const file = path.join(dir, 'exceptions.yaml');
  let text = '';
  try {
    text = await readFile(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== 'ENOENT') throw e;
  }
  const doc = parseDocument(text.trim() === '' ? `${HEADER}exceptions: []\n` : text);
  const list = doc.get('exceptions');
  if (isSeq(list)) {
    list.flow = false;
    list.add(doc.createNode(entry));
  } else {
    doc.set('exceptions', doc.createNode([entry]));
  }
  await mkdir(dir, { recursive: true });
  await writeFile(file, doc.toString(), 'utf8');
  return entry;
}
