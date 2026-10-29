import { loadCheckInstances, type CheckInstance } from '../checks/catalog.js';
import { CODE_SUBJECT_ID } from '../checks/context.js';
import { CHECK_TYPES } from '../checks/registry.js';
import type { Finding, ScanRecord } from '../findings/schema.js';
import { FindingsStore } from '../findings/store.js';
import { GLOBAL_CHECKS_DIR } from '../paths.js';
import { loadProject, type ProjectConfig } from '../project/schema.js';
import { SEVERITY_RANK, type CheckResult, type Severity } from '../types.js';

/**
 * The report as data. Markdown and PDF both render these blocks, so the two can never say different things. Every number, status
 * and sentence comes from the scan record and the check catalog; nothing is invented at report time.
 */
export type Tone = 'red' | 'yellow' | 'green';
export type Span = { text: string; bold?: boolean; code?: boolean; href?: string };
export type Block =
  | { kind: 'title'; text: string; meta: string }
  | { kind: 'verdict'; tone: Tone; text: string }
  | { kind: 'heading'; level: 2 | 3; text: string; severity?: Severity }
  | { kind: 'paragraph'; spans: Span[] }
  | { kind: 'fields'; items: Array<{ label: string; spans: Span[] }> }
  | { kind: 'list'; items: Span[][] }
  | { kind: 'table'; head: string[]; rows: string[][] };

export type Area = 'code' | 'web' | 'host';
export const AREAS: readonly Area[] = ['code', 'web', 'host'];
export const AREA_LABEL: Record<Area, string> = { code: 'Code', web: 'Websites and APIs', host: 'Servers' };

export interface ReportInput {
  project: ProjectConfig;
  record: ScanRecord;
  instances: ReadonlyMap<string, CheckInstance>;
}

const FIX_FIRST = 5;
const FIX_FIRST_CHARS = 160;

/** Check titles state the goal ("No secrets in the git history"); an open finding is that goal failing. */
function failedTitle(f: Finding): string {
  return `Failed: ${f.title}`;
}

/** The first sentence of the fix, cut to fit one or two lines. */
function shortFix(f: Finding): string | undefined {
  const first = fixText(f)?.split('\n')[0];
  if (!first) return undefined;
  const sentence = /^.*?[.!?](?=\s|$)/.exec(first)?.[0] ?? first;
  return sentence.length <= FIX_FIRST_CHARS ? sentence : `${sentence.slice(0, FIX_FIRST_CHARS - 1).trimEnd()}…`;
}

export function areaOf(instance: CheckInstance | undefined): Area {
  if (instance?.applies_to.includes('code')) return 'code';
  if (instance?.applies_to.includes('host')) return 'host';
  return 'web';
}

function areaOfTarget(input: ReportInput, checkId: string, target: string): Area {
  const instance = input.instances.get(checkId);
  if (instance) return areaOf(instance);
  if (target === CODE_SUBJECT_ID) return 'code';
  return input.project.hosts.some((h) => h.name === target) ? 'host' : 'web';
}

/** Where a finding is, in words: the target's URL, the server's name and address, or the project's code. */
export function whereOf(project: ProjectConfig, target: string): string {
  if (target === CODE_SUBJECT_ID) return "this project's code";
  const t = project.targets.find((x) => x.id === target);
  if (t) return t.url;
  const h = project.hosts.find((x) => x.name === target);
  if (h) return `${h.name} (${h.address})`;
  return target;
}

export function verdict(record: ScanRecord): { tone: Tone; text: string } {
  const open = record.findings.filter((f) => f.status === 'open');
  const urgent = open.filter((f) => f.severity === 'critical' || f.severity === 'high').length;
  const unverifiable = record.findings.filter((f) => f.status === 'unverifiable').length;
  if (urgent > 0) return { tone: 'red', text: `Needs attention: ${urgent} high-priority issue(s)` };
  if (open.length > 0) return { tone: 'yellow', text: `Some issues to fix: ${open.length} open` };
  if (unverifiable > 0) return { tone: 'yellow', text: `No issues found, but ${unverifiable} check(s) could not be verified` };
  return { tone: 'green', text: 'No issues found' };
}

/** "2026-10-28T10:00:00.000Z" → "2026-10-28 10:00 UTC". */
function formatTime(iso: string): string {
  return `${iso.slice(0, 10)} ${iso.slice(11, 16)} UTC`;
}

function bySeverity(a: Finding, b: Finding): number {
  return SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id);
}

/** The fix text without the "[any]" / "[nginx]" hint keys, one line per hint. */
function fixText(f: Finding): string | undefined {
  if (!f.fix) return undefined;
  return f.fix.how
    .split('\n')
    .map((line) => line.replace(/^\[[^\]]+\]\s*/, ''))
    .join('\n');
}

function resultFor(record: ScanRecord, f: Finding): CheckResult | undefined {
  return record.results.find((r) => r.check_id === f.check_id && r.target === f.target);
}

function atAGlance(input: ReportInput): Block[] {
  const rows: string[][] = [];
  for (const area of AREAS) {
    const results = input.record.results.filter((r) => areaOfTarget(input, r.check_id, r.target) === area);
    if (results.length === 0) continue;
    const issues = input.record.findings.filter((f) => f.status === 'open' && areaOfTarget(input, f.check_id, f.target) === area).length;
    const gaps = results.filter((r) => r.outcome === 'unverifiable' || r.outcome === 'error').length;
    rows.push([AREA_LABEL[area], String(results.length), String(issues), String(gaps)]);
  }
  return rows.length === 0 ? [] : [{ kind: 'heading', level: 2, text: 'At a glance' }, { kind: 'table', head: ['Area', 'Checks', 'Issues', 'Could not check'], rows }];
}

export interface FixItem {
  title: string;
  where: string;
  /** The first sentence of the fix. */
  fix?: string;
}

/** The open findings to deal with first: highest severity first, then by id. */
export function topFixes(input: ReportInput, limit: number): FixItem[] {
  return input.record.findings
    .filter((f) => f.status === 'open')
    .sort(bySeverity)
    .slice(0, limit)
    .map((f) => {
      const fix = shortFix(f);
      return { title: failedTitle(f), where: whereOf(input.project, f.target), ...(fix ? { fix } : {}) };
    });
}

function fixFirst(input: ReportInput): Block[] {
  const items = topFixes(input, FIX_FIRST).map((i): Span[] => [{ text: i.title, bold: true }, { text: ` — ${i.where}${i.fix ? ` — ${i.fix}` : ''}` }]);
  return items.length === 0 ? [] : [{ kind: 'heading', level: 2, text: 'Fix first' }, { kind: 'list', items }];
}

function findingsSection(input: ReportInput, open: Finding[]): Block[] {
  const blocks: Block[] = [{ kind: 'heading', level: 2, text: 'Findings' }];
  if (open.length === 0) return [...blocks, { kind: 'paragraph', spans: [{ text: 'No open findings.' }] }];
  for (const f of open) {
    const instance = input.instances.get(f.check_id);
    const result = resultFor(input.record, f);
    const how = fixText(f);
    const items: Array<{ label: string; spans: Span[] }> = [
      { label: 'Where', spans: [{ text: whereOf(input.project, f.target) }] },
      ...(result ? [{ label: 'What we found', spans: [{ text: result.observed }] }] : []),
      { label: 'Why it matters', spans: [{ text: instance?.why ?? f.title }] },
      ...(how ? [{ label: 'How to fix', spans: [{ text: how }] }] : []),
      ...(instance ? [{ label: 'Learn more', spans: [{ text: instance.source_url, href: instance.source_url }] }] : []),
      { label: 'Evidence', spans: f.evidence.flatMap((id, i) => [...(i > 0 ? [{ text: ', ' }] : []), { text: id, code: true }]) },
    ];
    blocks.push({ kind: 'heading', level: 3, text: failedTitle(f), severity: f.severity }, { kind: 'fields', items });
  }
  return blocks;
}

function couldNotVerify(input: ReportInput): Block[] {
  const gaps = input.record.findings.filter((f) => f.status === 'unverifiable').sort(bySeverity);
  if (gaps.length === 0) return [];
  const rows = gaps.map((f) => [f.title, whereOf(input.project, f.target), resultFor(input.record, f)?.observed ?? f.reasoning]);
  return [
    { kind: 'heading', level: 2, text: 'Could not verify' },
    { kind: 'table', head: ['Check', 'Where', 'Reason'], rows },
    { kind: 'paragraph', spans: [{ text: 'These are not passes: fix the cause and scan again.' }] },
  ];
}

function fixedSince(input: ReportInput): Block[] {
  const fixed = new Set(input.record.diff.fixed);
  const items = input.record.findings.filter((f) => fixed.has(f.id)).map((f): Span[] => [{ text: `${f.title} — ${whereOf(input.project, f.target)}` }]);
  return items.length === 0 ? [] : [{ kind: 'heading', level: 2, text: 'Fixed since the last scan' }, { kind: 'list', items }];
}

function passed(input: ReportInput): Block[] {
  const items: Span[][] = [];
  for (const area of AREAS) {
    const names = input.record.results
      .filter((r) => r.outcome === 'pass' && areaOfTarget(input, r.check_id, r.target) === area)
      .map((r) => (area === 'code' ? r.title : `${r.title} (${whereOf(input.project, r.target)})`));
    if (names.length > 0) items.push([{ text: `${AREA_LABEL[area]}: ${names.join(', ')}` }]);
  }
  return items.length === 0 ? [] : [{ kind: 'heading', level: 2, text: 'Passed' }, { kind: 'list', items }];
}

function about(input: ReportInput): Block[] {
  const scanned = new Set(input.record.results.map((r) => areaOfTarget(input, r.check_id, r.target)));
  const { project, record } = input;
  const lines: string[] = [];
  if (scanned.has('code')) lines.push("Code: this project's folder");
  if (scanned.has('web') && project.targets.length > 0) lines.push(`Websites and APIs: ${project.targets.map((t) => `${t.url} (${t.env})`).join(', ')}`);
  if (scanned.has('host') && project.hosts.length > 0) lines.push(`Servers: ${project.hosts.map((h) => `${h.name} (${h.address}, ${h.env})`).join(', ')}`);
  lines.push(record.consent_at ? `Scope confirmed by the person running the scan on ${formatTime(record.consent_at)}.` : 'Run from the command line.');
  lines.push(
    'Method: read-only requests to the listed systems and local reads of this folder; no AI, so the same inputs give the same result.',
    'A check that could not run is never counted as passed.',
    'Secret values are never shown, only the file, line and a fingerprint.',
  );
  return [{ kind: 'heading', level: 2, text: 'About this scan' }, { kind: 'list', items: lines.map((text) => [{ text }]) }];
}

export function buildReport(input: ReportInput): Block[] {
  const { project, record } = input;
  const open = record.findings.filter((f) => f.status === 'open').sort(bySeverity);
  const v = verdict(record);
  return [
    { kind: 'title', text: `Security report: ${project.name}`, meta: `Scanned ${formatTime(record.scanned_at)} from network "${record.scan_label}" · deterministic scan, no AI` },
    { kind: 'verdict', tone: v.tone, text: v.text },
    ...atAGlance(input),
    ...fixFirst(input),
    ...findingsSection(input, open),
    ...couldNotVerify(input),
    ...fixedSince(input),
    ...passed(input),
    ...about(input),
  ];
}

/** The latest scan with its project and check catalog, or undefined before the first scan. */
export async function loadReportInput(projectDir: string, deps: { checksDir?: string } = {}): Promise<ReportInput | undefined> {
  const record = await new FindingsStore(projectDir).latest();
  if (!record) return undefined;
  const project = await loadProject(projectDir);
  const instances = await loadCheckInstances(deps.checksDir ?? GLOBAL_CHECKS_DIR, CHECK_TYPES);
  return { project, record, instances: new Map(instances.map((i) => [i.id, i])) };
}
