import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';
import type { ScanRecord } from '../findings/schema.js';
import { GLOBAL_CHECKLISTS_DIR } from '../paths.js';
import { SEVERITIES, type Outcome } from '../types.js';
import { KbError } from './lesson.js';
import { loadSourceHosts, sourceProblem } from './sources.js';

const Id = z.string().regex(/^[a-z0-9][a-z0-9-]*$/, 'use lowercase letters, digits and dashes');

/** One rule a person or an AI assistant checks by reading the code and configuration; the scan cannot decide it. */
export const ChecklistItemSchema = z
  .object({
    id: Id,
    title: z.string().min(1),
    severity: z.enum(SEVERITIES),
    /** When the item is relevant; without it, the item always applies. */
    applies_if: z.string().min(1).optional(),
    why: z.string().min(1),
    look_for: z.array(z.string().min(1)).min(1),
    fail_if: z.string().min(1),
    pass_if: z.string().min(1),
    evidence: z.string().min(1),
    fix: z.string().min(1),
    source_url: z.url({ protocol: /^https$/ }),
    /** Scan checks that decide part of the item; their latest outcomes are shown next to it. */
    automated_by: z.array(Id).default([]),
  })
  .strict();

export const ChecklistSchema = z
  .object({
    area: Id,
    title: z.string().min(1),
    /** Position in the rendered checklist: lower first, then by area. */
    order: z.number().int().default(100),
    items: z.array(ChecklistItemSchema).min(1),
  })
  .strict();

export type ChecklistItem = z.infer<typeof ChecklistItemSchema>;
export type Checklist = z.infer<typeof ChecklistSchema>;

export interface ChecklistRules {
  /** Ids of the check catalogue; automated_by must name one of them. */
  checkIds: ReadonlySet<string>;
  /** The source allowlist (knowledge/sources.yaml). */
  sourceHosts: ReadonlySet<string>;
}

/** Loads every <area>.yaml in dir, sorted by order then area. Any invalid file, duplicate id, unknown check or unlisted source throws. */
export async function loadChecklists(dir: string, rules: ChecklistRules): Promise<Checklist[]> {
  const files = (await readdir(dir)).filter((f) => f.endsWith('.yaml')).sort();
  const lists: Checklist[] = [];
  const errors: string[] = [];
  const ids = new Set<string>();
  for (const file of files) {
    let raw: unknown;
    try {
      raw = parse(await readFile(path.join(dir, file), 'utf8'));
    } catch (e) {
      errors.push(`${file}: invalid YAML: ${(e as Error).message}`);
      continue;
    }
    const parsed = ChecklistSchema.safeParse(raw);
    if (!parsed.success) {
      errors.push(...parsed.error.issues.map((i) => `${file}: ${i.path.join('.') || '(root)'}: ${i.message}`));
      continue;
    }
    const list = parsed.data;
    if (`${list.area}.yaml` !== file) errors.push(`${file}: area "${list.area}" must match the file name`);
    for (const item of list.items) {
      if (ids.has(item.id)) errors.push(`${file}: duplicate item id "${item.id}"`);
      ids.add(item.id);
      for (const check of item.automated_by) if (!rules.checkIds.has(check)) errors.push(`${file}: ${item.id}: automated_by names unknown check "${check}"`);
      const problem = sourceProblem(item.source_url, rules.sourceHosts);
      if (problem) errors.push(`${file}: ${item.id}: ${problem}`);
    }
    lists.push(list);
  }
  if (errors.length > 0) throw new KbError(`Invalid checklists in ${dir}:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
  return lists.sort((a, b) => a.order - b.order || a.area.localeCompare(b.area));
}

/** The checklists shipped in knowledge/checklists, checked against the given check catalogue and the source allowlist. */
export async function loadShippedChecklists(checks: readonly { id: string }[]): Promise<Checklist[]> {
  return loadChecklists(GLOBAL_CHECKLISTS_DIR, { checkIds: new Set(checks.map((c) => c.id)), sourceHosts: await loadSourceHosts() });
}

/** Keeps the named areas, in the order given; throws on an area that does not exist. Empty keeps all. */
export function selectAreas(lists: readonly Checklist[], areas: readonly string[]): Checklist[] {
  if (areas.length === 0) return [...lists];
  return areas.map((a) => {
    const list = lists.find((l) => l.area === a);
    if (!list) throw new KbError(`Unknown checklist area "${a}". Areas: ${lists.map((l) => l.area).join(', ')}`);
    return list;
  });
}

const OUTCOME_WORD: Record<Outcome, string> = { pass: 'passed', fail: 'failed', unverifiable: 'could not verify', error: 'error' };

/** "hdr-hsts: passed on app, failed on api" from the latest scan, or why there is no outcome. */
function automatedLine(check: string, record: ScanRecord | undefined): string {
  if (!record) return `\`${check}\`: no scan yet`;
  const results = record.results.filter((r) => r.check_id === check);
  if (results.length === 0) return `\`${check}\`: not in the latest scan`;
  return `\`${check}\`: ${results.map((r) => `${OUTCOME_WORD[r.outcome]} on ${r.target}`).join(', ')}`;
}

/** The checklist as Markdown for a person or an AI assistant, with the latest scan's outcome for automated items. */
export function renderChecklist(lists: readonly Checklist[], record?: ScanRecord): string {
  const items = lists.flatMap((l) => l.items);
  const lines = [
    '# Security review checklist',
    '',
    `${items.length} rules for what an attacker tries first that the scan cannot decide on its own: they need someone to read the code and the cloud and CI configuration. Items the scan covers in part say so under **Automated**.`,
    '',
    'How to work through it (by hand, or by giving this file to an AI assistant that can read the code):',
    '',
    '1. Skip an item whose **Applies if** does not hold, and say that you skipped it.',
    '2. Follow **Look for**, then answer pass, fail or unknown using **Fail if** and **Pass if**.',
    '3. Back every answer with the **Evidence** asked for, such as file:line or a configuration value. No evidence means unknown, not pass.',
    '4. The answers are an assessment by whoever worked through the list, not secagent scan results. Re-run `secagent scan` after fixing anything it checks.',
    '',
    record ? `Automated outcomes are from the scan of ${record.scanned_at.slice(0, 16).replace('T', ' ')} UTC.` : 'No scan yet: automated outcomes are not shown. Run `secagent` first to fill them in.',
    '',
    '| Item | Severity | Automated |',
    '|---|---|---|',
    ...items.map((i) => `| \`${i.id}\` ${i.title} | ${i.severity} | ${i.automated_by.length > 0 ? 'in part' : 'no'} |`),
  ];
  for (const list of lists) {
    lines.push('', `## ${list.title}`);
    for (const i of list.items) {
      lines.push('', `### \`${i.id}\`: ${i.title}`, '', `Severity: ${i.severity}`, '');
      if (i.applies_if) lines.push(`**Applies if:** ${i.applies_if}`, '');
      lines.push(`**Why:** ${i.why}`, '', '**Look for:**', '', ...i.look_for.map((l) => `- ${l}`), '');
      lines.push(`**Fail if:** ${i.fail_if}`, '', `**Pass if:** ${i.pass_if}`, '', `**Evidence:** ${i.evidence}`, '', `**Fix:** ${i.fix}`, '');
      if (i.automated_by.length > 0) lines.push(`**Automated:** ${i.automated_by.map((c) => automatedLine(c, record)).join('; ')}`, '');
      lines.push(`**Source:** ${i.source_url}`);
    }
  }
  lines.push('');
  return lines.join('\n');
}
