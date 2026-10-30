import { ObservationError } from '../checks/errors.js';
import { KbError } from '../kb/lesson.js';
import { loadProject } from '../project/schema.js';
import { ScopeError } from '../project/scope.js';
import type { Choice } from '../ui/prompt.js';
import type { Style } from '../ui/style.js';
import { askPlan, type AskDeps, type WizardPlan } from '../wizard/questions.js';
import { askDepsFor, reviewLessons, savePlan, scanAndReport, type WizardDeps } from '../wizard/steps.js';
import { acceptedRisks, addCollectorOutput, checkCveClaim, checkSetup, connectAi, exportChecklist, openReport, showFixes, showGuides } from './actions.js';
import { suggestNext, type HomeAction, type Suggestion } from './next.js';
import { projectStatus, type ProjectStatus } from './status.js';

export interface HomeSession {
  /** The plan this session scanned with: a rescan reuses it, and its consent, without asking again. */
  plan?: WizardPlan;
}

const LABEL: Record<HomeAction, string> = {
  fixes: 'See what to fix first',
  scan: 'Scan again',
  report: 'Open the report',
  checklist: "Review what the scan can't see",
  collector: "Add a server's collector output",
  risks: 'Accepted risks',
  verify: "Check a scanner's CVE claim",
  lessons: 'Review lessons an AI assistant proposed',
  ai: 'Connect an AI assistant',
  settings: 'Settings and setup',
  help: 'How secagent works',
  exit: 'Exit',
};

function ago(days: number): string {
  return days === 0 ? 'today' : days === 1 ? 'yesterday' : `${days} days ago`;
}

/** The status block: what is set up, how the last scan went, and the suggested next step with its reason. */
export function renderStatus(s: ProjectStatus, next: Suggestion, style: Style): string {
  const lines = [`${style.bold(`secagent · ${s.name}`)}  ${style.dim(`(${[s.stack.length > 0 ? s.stack.join(', ') : 'stack not detected', s.git ? 'git' : 'no git'].join(', ')})`)}`, ''];
  const row = (label: string, text: string) => lines.push(`  ${label.padEnd(11)} ${text}`);
  const scan = s.lastScan;
  if (scan) {
    const counts = scan.open.map(([severity, n]) => `${severity} ${n}`).join(', ');
    row('Last scan', [ago(scan.ageDays), scan.verdict.text, ...(counts ? [counts] : []), ...(scan.unverifiable > 0 ? [`${scan.unverifiable} could not be checked`] : [])].join(' · '));
  } else row('Last scan', 'never');
  row('Websites', s.websites.length > 0 ? s.websites.map((w) => `${w.url} (${w.env})`).join(', ') : 'none listed');
  const collector = { none: ' · no collector output yet', stale: ' · collector output is stale', fresh: '' } as const;
  row('Servers', s.servers.length > 0 ? s.servers.map((h) => `${h.name} (${h.env})${collector[h.collector]}`).join(', ') : 'none listed');
  const soonest = s.accepted[0];
  if (soonest) row('Accepted', `${s.accepted.length} risk(s); the soonest ends ${soonest.daysLeft === 0 ? 'today' : `in ${soonest.daysLeft} day(s)`}`);
  if (s.pendingLessons > 0) row('Lessons', `${s.pendingLessons} waiting for your review`);
  lines.push('', `  ${style.bold('Next:')} ${next.text}`, '');
  return `\n${lines.join('\n')}\n`;
}

/** The menu: only items that apply, the suggested one first. */
export function menuFor(s: ProjectStatus, next: Suggestion): Array<Choice<HomeAction>> {
  const open = s.lastScan?.open.reduce((n, [, count]) => n + count, 0) ?? 0;
  const items: Array<[HomeAction, boolean, string | undefined]> = [
    ['fixes', open > 0, `${open} open`],
    ['scan', true, undefined],
    ['report', s.lastScan !== undefined, undefined],
    ['checklist', true, 'a checklist for you or your AI'],
    ['collector', s.servers.length > 0, undefined],
    ['risks', open > 0 || s.accepted.length > 0, s.accepted.length > 0 ? `${s.accepted.length} accepted` : undefined],
    ['verify', s.servers.length > 0, undefined],
    ['lessons', s.pendingLessons > 0, `${s.pendingLessons} waiting`],
    ['ai', true, undefined],
    ['settings', true, 'change what is checked, start over, check this machine'],
    ['help', true, 'step-by-step guides'],
    ['exit', true, undefined],
  ];
  const choices = items
    .filter(([, shown]) => shown)
    .map(([value, , hint]) => {
      const label = value === 'scan' && !s.lastScan ? 'Run the first scan' : LABEL[value];
      const marked = [...(value === next.action ? ['suggested'] : []), ...(hint ? [hint] : [])].join(' · ');
      return { value, label, ...(marked ? { hint: marked } : {}) };
    });
  return [...choices.filter((c) => c.value === next.action), ...choices.filter((c) => c.value !== next.action)];
}

/** Runs an action; an error the person can do something about is shown, and the home screen comes back. */
async function softly<T>(deps: WizardDeps, run: () => Promise<T>): Promise<T | undefined> {
  try {
    return await run();
  } catch (e) {
    if (!(e instanceof ObservationError || e instanceof KbError || e instanceof ScopeError)) throw e;
    deps.out.write(`${deps.style.red(e.message)}\n`);
    return undefined;
  }
}

/** Scans with this session's plan. Without one (a new session), or with new settings, it asks first, consent included. */
async function scanAgain(dir: string, deps: WizardDeps, session: HomeSession, start: NonNullable<AskDeps['start']>): Promise<void> {
  const now = deps.now ?? (() => new Date());
  let plan = start === 'again' ? session.plan : undefined;
  if (!plan) {
    plan = await askPlan(deps.prompter, await askDepsFor(dir, now, { existing: await loadProject(dir), start }));
    if (!plan) {
      deps.out.write('Nothing was changed and nothing was scanned.\n');
      return;
    }
    await savePlan(dir, plan, now);
    session.plan = plan;
  }
  await scanAndReport(dir, plan, deps);
}

async function settings(dir: string, deps: WizardDeps, session: HomeSession): Promise<void> {
  const choice = await deps.prompter.select({
    message: 'Settings and setup',
    choices: [
      { value: 'change' as const, label: 'Change what is checked', hint: 'websites, servers, network; then scan' },
      { value: 'fresh' as const, label: 'Start over', hint: 'every question again; then scan' },
      { value: 'doctor' as const, label: 'Check this machine', hint: 'Node, git, the project, the advisory database' },
      { value: 'back' as const, label: 'Back' },
    ],
    default: 'back' as const,
  });
  if (choice === 'change' || choice === 'fresh') await scanAgain(dir, deps, session, choice);
  else if (choice === 'doctor') await checkSetup(dir, deps);
}

/** The home screen: status, the suggested next step, the menu; again after every action, until Exit. */
export async function runHome(dir: string, deps: WizardDeps, session: HomeSession): Promise<number> {
  const { prompter, out, style } = deps;
  const now = deps.now ?? (() => new Date());
  for (;;) {
    const status = await projectStatus(dir, now());
    const next = suggestNext(status);
    out.write(renderStatus(status, next, style));
    prompter.discardPending?.();
    const action = await prompter.select({ message: 'What do you want to do?', choices: menuFor(status, next), default: next.action });
    switch (action) {
      case 'exit':
        return 0;
      case 'scan':
        await scanAgain(dir, deps, session, 'again');
        break;
      case 'settings':
        await settings(dir, deps, session);
        break;
      case 'risks':
        if (await softly(deps, () => acceptedRisks(dir, deps))) await scanAgain(dir, deps, session, 'again');
        break;
      case 'fixes':
        await softly(deps, () => showFixes(dir, deps));
        break;
      case 'report':
        await softly(deps, () => openReport(dir, deps));
        break;
      case 'checklist':
        await softly(deps, () => exportChecklist(dir, deps));
        break;
      case 'collector':
        await softly(deps, () => addCollectorOutput(dir, deps, next.host));
        break;
      case 'verify':
        await softly(deps, () => checkCveClaim(dir, deps));
        break;
      case 'lessons':
        await softly(deps, () => reviewLessons(dir, deps, now));
        break;
      case 'ai':
        connectAi(dir, deps);
        break;
      case 'help':
        await showGuides(deps);
        break;
    }
  }
}
