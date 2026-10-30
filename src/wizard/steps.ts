import { spawn } from 'node:child_process';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Advisories } from '../advisories/types.js';
import type { ScanRecord } from '../findings/schema.js';
import { makeCollector } from '../host/collector.js';
import { SnapshotStore } from '../host/store.js';
import { acceptRisk } from '../kb/accept.js';
import { KbError } from '../kb/lesson.js';
import { approveLesson, pendingLessons, rejectLesson } from '../kb/write.js';
import type { NetClient } from '../net/scoped.js';
import { recordConsent } from '../project/consent.js';
import { initProject } from '../project/init.js';
import { saveProject, type ProjectConfig } from '../project/schema.js';
import { detectStack, type StackDetection } from '../project/stack.js';
import { AREA_LABEL, topFixes, verdict, whereOf, type Area, type ReportInput } from '../report/model.js';
import { scanNoAi } from '../scan/no-ai.js';
import type { Prompter } from '../ui/prompt.js';
import { SYMBOL, type Style } from '../ui/style.js';
import { SEVERITIES, type CheckResult } from '../types.js';
import type { AskDeps, WizardPlan } from './questions.js';

export interface WizardDeps {
  prompter: Prompter;
  out: NodeJS.WritableStream;
  style: Style;
  now?: () => Date;
  /** Injected network and advisory sources (tests); the scan uses the live ones otherwise. */
  net?: NetClient;
  advisories?: Advisories;
  /** The setup check's request to the advisory database (tests); defaults to fetch. */
  fetchImpl?: typeof fetch;
  /** Opens a file in the system viewer; false when that was not possible. */
  openFile?: (file: string) => Promise<boolean>;
}

/** Opens a file with the system's default program, detached from this process. */
export function openWithSystem(file: string): Promise<boolean> {
  const [command, args] =
    process.platform === 'darwin' ? ['open', [file]] : process.platform === 'win32' ? ['cmd', ['/c', 'start', '', file]] : ['xdg-open', [file]];
  return new Promise((resolve) => {
    const child = spawn(command as string, args as string[], { detached: true, stdio: 'ignore' });
    child.once('error', () => resolve(false));
    child.once('spawn', () => {
      child.unref();
      resolve(true);
    });
  });
}

export async function exists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

function symbolFor(r: CheckResult, style: Style): string {
  switch (r.outcome) {
    case 'pass':
      return style.green(SYMBOL.pass);
    case 'fail':
      return style.red(SYMBOL.fail);
    case 'unverifiable':
      return style.yellow(SYMBOL.unverifiable);
    case 'error':
      return style.red(SYMBOL.error);
  }
}

function toneOf(style: Style, tone: 'red' | 'yellow' | 'green'): (s: string) => string {
  return (s) => style.bold(tone === 'red' ? style.red(s) : tone === 'yellow' ? style.yellow(s) : style.green(s));
}

/** "your code, 2 website(s) and 1 server(s)": what this scan covers, in words. */
function scopeOf(plan: WizardPlan): string {
  const parts = [
    ...(plan.groups.includes('code') ? ['your code'] : []),
    ...(plan.groups.includes('web') ? [`${plan.config.targets.length} website(s)`] : []),
    ...(plan.groups.includes('host') ? [`${plan.config.hosts.length} server(s)`] : []),
  ];
  return parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}` : (parts[0] ?? 'nothing');
}

/** Runs the scan, printing one line per check as it finishes. */
export async function scanWithProgress(dir: string, plan: WizardPlan, deps: WizardDeps): Promise<ScanRecord> {
  const { out, style } = deps;
  let total = 0;
  let done = 0;
  let current: string | undefined;
  return scanNoAi(dir, {
    only: plan.groups,
    trigger: 'wizard',
    ...(plan.consentAt ? { consentAt: plan.consentAt } : {}),
    ...(deps.now ? { now: deps.now } : {}),
    ...(deps.net ? { net: deps.net } : {}),
    ...(deps.advisories ? { advisories: deps.advisories } : {}),
    onPlan: (n) => {
      total = n;
      out.write(`\n${style.bold(`I'm running ${n} checks on ${scopeOf(plan)}.`)}\n`);
    },
    onResult: (r, group) => {
      const area: Area = group;
      if (current !== area) {
        current = area;
        out.write(`\n${style.bold(AREA_LABEL[area])}\n`);
      }
      done += 1;
      const where = group === 'code' ? '' : `  ${style.dim(whereOf(plan.config, r.target))}`;
      out.write(`  ${symbolFor(r, style)} ${style.dim(`${done}/${total}`)}  ${r.title}${where}\n`);
    },
  });
}

export function showResult(record: ScanRecord, input: ReportInput, deps: WizardDeps): void {
  const { out, style } = deps;
  const v = verdict(record);
  out.write(`\n${toneOf(style, v.tone)(v.text)}\n`);
  const open = record.findings.filter((f) => f.status === 'open');
  const counts = SEVERITIES.map((s) => [s, open.filter((f) => f.severity === s).length] as const).filter(([, n]) => n > 0);
  if (counts.length > 0) out.write(`  ${counts.map(([s, n]) => `${s} ${n}`).join(' · ')}\n`);
  const gaps = record.findings.filter((f) => f.status === 'unverifiable').length;
  if (gaps > 0) out.write(`  ${gaps} check(s) could not be verified (see the report)\n`);
  const fixes = topFixes(input, 3);
  if (fixes.length > 0) {
    out.write(`\n${style.bold('Fix first')}\n`);
    fixes.forEach((f, i) => {
      out.write(`  ${i + 1}. ${f.title} ${style.dim(`— ${f.where}`)}\n`);
      if (f.fix) out.write(`     ${f.fix}\n`);
    });
  }
}

/** Saves the plan: settings, then any collector output. */
export async function savePlan(dir: string, plan: WizardPlan, now: () => Date): Promise<void> {
  await initProject(dir, { name: plan.config.name });
  await saveProject(dir, plan.config);
  if (plan.consentAt) await recordConsent(dir, plan.config, plan.consentAt);
  const store = new SnapshotStore(dir, now);
  for (const s of plan.snapshots) await store.add(s.host, s.text);
}

export async function writeCollectorFile(dir: string, host: string): Promise<string> {
  const bundle = await makeCollector(dir, host);
  await mkdir(bundle.dropDir, { recursive: true });
  const file = path.join(bundle.dropDir, 'collector.sh');
  await writeFile(file, bundle.script, { encoding: 'utf8', mode: 0o755 });
  return file;
}

/** Asks which finding, who, why and until when; true when the risk was accepted (the scan then runs again to show it). */
export async function acceptFromMenu(dir: string, input: ReportInput, open: ScanRecord['findings'], deps: WizardDeps, now: () => Date): Promise<boolean> {
  const { prompter, out } = deps;
  const findingId = await prompter.select({ message: 'Which finding?', choices: open.map((f) => ({ value: f.id, label: `${f.severity.toUpperCase()}: ${f.title}`, hint: whereOf(input.project, f.target) })) });
  const owner = await prompter.text({ message: 'Your name (who accepts this risk)', validate: (v) => (v.trim() === '' ? 'Enter a name' : undefined) });
  const reason = await prompter.text({ message: 'Why is it acceptable for now? (at least 10 characters)', validate: (v) => (v.trim().length < 10 ? 'Say a little more' : undefined) });
  const soon = new Date(now().getTime() + 30 * 86_400_000).toISOString().slice(0, 10);
  const until = (await prompter.text({ message: 'Until when? (YYYY-MM-DD, at most a year)', default: soon })).trim();
  try {
    const entry = await acceptRisk(dir, { findingId, owner, reason, until }, now());
    out.write(`Accepted ${entry.finding_id} until ${entry.expires}. Scanning again to update the report.\n`);
    return true;
  } catch (e) {
    if (!(e instanceof KbError)) throw e;
    out.write(`${e.message}\n`);
    return false;
  }
}

/** Shows each lesson an AI assistant proposed, with its source and quote, and lets the person approve, reject or skip it. */
export async function reviewLessons(dir: string, deps: WizardDeps, now: () => Date): Promise<void> {
  const { prompter, out } = deps;
  for (const l of await pendingLessons(dir)) {
    out.write(`\n${l.title}\n  source: ${l.source_url ?? '-'}\n  quote:  "${l.quote ?? ''}"\n  ${l.body.split('\n')[0]?.slice(0, 240) ?? ''}\n`);
    const choice = await prompter.select({
      message: `${l.id}:`,
      choices: [
        { value: 'skip' as const, label: 'Decide later' },
        { value: 'approve' as const, label: 'Approve (it can then back lowering a risk)' },
        { value: 'reject' as const, label: 'Reject and delete' },
      ],
      default: 'skip' as const,
    });
    if (choice === 'approve') {
      const by = await prompter.text({ message: 'Your name', validate: (v) => (v.trim() === '' ? 'Enter a name' : undefined) });
      await approveLesson(dir, l.id, by, now());
      out.write('Approved.\n');
    } else if (choice === 'reject') {
      await rejectLesson(dir, l.id);
      out.write('Rejected and removed.\n');
    }
  }
}

/** What the setup questions need: the folder, its stack, file reading and the collector writer. */
export async function askDepsFor(
  dir: string,
  now: () => Date,
  extra: { existing?: ProjectConfig; start?: AskDeps['start']; detection?: StackDetection } = {},
): Promise<AskDeps> {
  return {
    dir,
    ...(extra.existing ? { existing: extra.existing } : {}),
    ...(extra.start ? { start: extra.start } : {}),
    detection: extra.detection ?? (await detectStack(dir)),
    now,
    readFile: (file) => readFile(file, 'utf8'),
    writeCollector: (host) => writeCollectorFile(dir, host),
  };
}
