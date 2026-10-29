import { spawn } from 'node:child_process';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Advisories } from '../advisories/types.js';
import { CatalogError } from '../checks/catalog.js';
import { ObservationError } from '../checks/errors.js';
import { repoState } from '../code/git.js';
import { acceptRisk } from '../kb/accept.js';
import { KbError } from '../kb/lesson.js';
import { approveLesson, pendingLessons, rejectLesson } from '../kb/write.js';
import type { ScanRecord } from '../findings/schema.js';
import { makeCollector } from '../host/collector.js';
import { SnapshotStore } from '../host/store.js';
import type { NetClient } from '../net/scoped.js';
import { recordConsent } from '../project/consent.js';
import { initProject } from '../project/init.js';
import { loadProject, ProjectConfigError, projectFile, saveProject, type ProjectConfig } from '../project/schema.js';
import { ScopeError } from '../project/scope.js';
import { detectStack } from '../project/stack.js';
import { AREA_LABEL, loadReportInput, topFixes, verdict, whereOf, type Area, type ReportInput } from '../report/model.js';
import { writeReport } from '../report/write.js';
import { scanNoAi } from '../scan/no-ai.js';
import { PromptCancelled, type Prompter } from '../ui/prompt.js';
import { SYMBOL, type Style } from '../ui/style.js';
import { SEVERITIES, type CheckResult } from '../types.js';
import { askPlan, type WizardPlan } from './questions.js';

export interface WizardDeps {
  prompter: Prompter;
  out: NodeJS.WritableStream;
  style: Style;
  now?: () => Date;
  /** Injected network and advisory sources (tests); the scan uses the live ones otherwise. */
  net?: NetClient;
  advisories?: Advisories;
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

async function exists(file: string): Promise<boolean> {
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

/** Runs the scan, printing one line per check as it finishes. */
async function scanWithProgress(dir: string, plan: WizardPlan, deps: WizardDeps): Promise<ScanRecord> {
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
      out.write(`\n${style.bold(`Scanning (${n} checks)`)}\n`);
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

function showResult(record: ScanRecord, input: ReportInput, deps: WizardDeps): void {
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
async function savePlan(dir: string, plan: WizardPlan, now: () => Date): Promise<void> {
  await initProject(dir, { name: plan.config.name });
  await saveProject(dir, plan.config);
  if (plan.consentAt) await recordConsent(dir, plan.config, plan.consentAt);
  const store = new SnapshotStore(dir, now);
  for (const s of plan.snapshots) await store.add(s.host, s.text);
}

async function writeCollectorFile(dir: string, host: string): Promise<string> {
  const bundle = await makeCollector(dir, host);
  await mkdir(bundle.dropDir, { recursive: true });
  const file = path.join(bundle.dropDir, 'collector.sh');
  await writeFile(file, bundle.script, { encoding: 'utf8', mode: 0o755 });
  return file;
}

/** Asks which finding, who, why and until when; true when the risk was accepted (the scan then runs again to show it). */
async function acceptFromMenu(dir: string, input: ReportInput, open: ScanRecord['findings'], deps: WizardDeps, now: () => Date): Promise<boolean> {
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
async function reviewLessons(dir: string, deps: WizardDeps, now: () => Date): Promise<void> {
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

/**
 * The guided scan: asks what to check, saves the answers, scans with live progress, writes the Markdown and PDF report and shows
 * the result. Returns the exit code: 0 done, 130 cancelled, 1 for a problem with the settings or the scan.
 */
export async function runWizard(dir: string, deps: WizardDeps): Promise<number> {
  const { prompter, out, style } = deps;
  const now = deps.now ?? (() => new Date());
  const openFile = deps.openFile ?? openWithSystem;
  try {
    out.write(`\n${style.bold('secagent')} · security check for this project\n`);
    const detection = await detectStack(dir);
    const git = await repoState(dir);
    const stack = Object.values(detection.stack).filter((v): v is string => typeof v === 'string');
    out.write(`  Folder: ${dir}\n  Stack: ${stack.length > 0 ? stack.join(', ') : 'not detected'}\n  Git: ${git.state === 'repo' ? 'repository' : 'not a repository'}\n\n`);

    let existing: ProjectConfig | undefined;
    if (await exists(projectFile(dir))) {
      try {
        existing = await loadProject(dir);
      } catch (e) {
        if (!(e instanceof ProjectConfigError)) throw e;
        out.write(`${style.red(e.message)}\nFix it, or delete it to start over.\n`);
        return 1;
      }
    }

    const plan = await askPlan(prompter, {
      dir,
      ...(existing ? { existing } : {}),
      detection,
      now,
      readFile: (file) => readFile(file, 'utf8'),
      writeCollector: (host) => writeCollectorFile(dir, host),
    });
    if (!plan) {
      out.write('Nothing was saved and nothing was scanned.\n');
      return 0;
    }
    await savePlan(dir, plan, now);

    for (;;) {
      const record = await scanWithProgress(dir, plan, deps);
      const input = await loadReportInput(dir);
      if (!input) throw new Error('the scan did not leave a record to report on');
      const { latest } = await writeReport(dir, input, { formats: ['md', 'pdf', 'html'] });
      showResult(record, input, deps);
      const [md, pdf, html] = latest;
      out.write(`\n${style.bold('Report')}\n  Markdown: ${md}\n  PDF:      ${pdf}\n  HTML:     ${html}\n\n`);

      let rescan = false;
      while (!rescan) {
        prompter.discardPending?.();
        const open = record.findings.filter((f) => f.status === 'open');
        const pending = await pendingLessons(dir).catch(() => []);
        const next = await prompter.select({
          message: 'What next?',
          choices: [
            { value: 'open' as const, label: 'Open the PDF report' },
            { value: 'html' as const, label: 'Open the HTML report' },
            ...(open.length > 0 ? [{ value: 'accept' as const, label: 'Accept the risk of a finding for now', hint: `${open.length} open` }] : []),
            ...(pending.length > 0 ? [{ value: 'lessons' as const, label: 'Review lessons an AI assistant proposed', hint: `${pending.length} waiting` }] : []),
            { value: 'again' as const, label: 'Scan again' },
            { value: 'exit' as const, label: 'Exit' },
          ],
          default: 'exit' as const,
        });
        if (next === 'exit') return 0;
        if (next === 'again') rescan = true;
        else if (next === 'open' || next === 'html') {
          const file = next === 'open' ? pdf : html;
          if (file && !(await openFile(file))) out.write(`Could not open it from here: ${file}\n`);
        } else if (next === 'accept') {
          rescan = await acceptFromMenu(dir, input, open, deps, now);
        } else {
          await reviewLessons(dir, deps, now);
        }
      }
    }
  } catch (e) {
    if (e instanceof PromptCancelled) {
      out.write('\nCancelled.\n');
      return 130;
    }
    if (e instanceof ProjectConfigError || e instanceof ScopeError || e instanceof CatalogError || e instanceof ObservationError || e instanceof KbError) {
      out.write(`${style.red(e.message)}\n`);
      return 1;
    }
    throw e;
  }
}
