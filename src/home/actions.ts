import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createAdvisories } from '../advisories/index.js';
import { loadCheckInstances } from '../checks/catalog.js';
import { CHECK_TYPES } from '../checks/registry.js';
import { doctor, formatDoctor } from '../doctor.js';
import { EvidenceStore } from '../evidence/store.js';
import type { Finding } from '../findings/schema.js';
import { FindingsStore } from '../findings/store.js';
import { renderGuide } from '../help/render.js';
import { GUIDES } from '../help/topics.js';
import { SnapshotStore } from '../host/store.js';
import { loadShippedChecklists, renderChecklist, selectAreas } from '../kb/checklist.js';
import { mcpSetupLines } from '../mcp/setup.js';
import { GLOBAL_CHECKS_DIR, projectStateDir } from '../paths.js';
import { loadProject, type ProjectConfig } from '../project/schema.js';
import { Scope } from '../project/scope.js';
import { fixText, loadReportInput, whereOf, type ReportInput } from '../report/model.js';
import { SEVERITY_RANK } from '../types.js';
import type { Prompter } from '../ui/prompt.js';
import type { Style } from '../ui/style.js';
import { verifyClaim } from '../verify/claim.js';
import { formatClaim } from '../verify/format.js';
import { askSnapshot, collectorSteps } from '../wizard/questions.js';
import { acceptFromMenu, exists, openWithSystem, writeCollectorFile, type WizardDeps } from '../wizard/steps.js';
import { checklistFile, projectStatus } from './status.js';

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
const INDENT = '\n            ';

function nowOf(deps: WizardDeps): () => Date {
  return deps.now ?? (() => new Date());
}

/** One finding in plain words, from the same fields the report uses. */
export function findingDetail(input: ReportInput, f: Finding, style: Style): string {
  const observed = input.record.results.find((r) => r.check_id === f.check_id && r.target === f.target)?.observed;
  const why = input.instances.get(f.check_id)?.why?.trim();
  const fix = fixText(f);
  const sideEffects = f.fix?.side_effects ?? [];
  return [
    `${style.bold(`Failed: ${f.title}`)}  ${style.dim(f.severity)}`,
    `  Where     ${whereOf(input.project, f.target)}`,
    ...(observed ? [`  Found     ${observed}`] : []),
    ...(why ? [`  Why       ${why.split('\n').join(INDENT)}`] : []),
    ...(fix ? [`  Fix       ${fix.split('\n').join(INDENT)}`] : []),
    ...(sideEffects.length > 0 ? [`  Watch out ${sideEffects.join(INDENT)}`] : []),
    `  Evidence  ${f.evidence.join(', ')}`,
  ].join('\n');
}

/** The open findings, most urgent first; pick one to see what to change. */
export async function showFixes(dir: string, deps: WizardDeps): Promise<void> {
  const { prompter, out, style } = deps;
  const input = await loadReportInput(dir);
  const open = (input?.record.findings ?? [])
    .filter((f) => f.status === 'open')
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id));
  if (!input || open.length === 0) {
    out.write('\nNothing is open, so there is nothing to fix right now.\n');
    return;
  }
  out.write(`\n${style.bold(`I found ${open.length} thing(s) to fix. Most urgent first:`)}\n`);
  for (;;) {
    const id = await prompter.select({
      message: 'Which one should I explain?',
      choices: [...open.map((f) => ({ value: f.id, label: `${f.severity.toUpperCase()}: ${f.title}`, hint: whereOf(input.project, f.target) })), { value: '', label: 'Back' }],
      default: open[0]?.id ?? '',
    });
    const f = open.find((x) => x.id === id);
    if (!f) return;
    out.write(`\n${findingDetail(input, f, style)}\n\n`);
  }
}

export async function openReport(dir: string, deps: WizardDeps): Promise<void> {
  const { prompter, out } = deps;
  const reports = path.join(projectStateDir(dir), 'reports');
  const which = await prompter.select({
    message: 'Which report?',
    choices: [
      { value: 'pdf' as const, label: 'PDF' },
      { value: 'html' as const, label: 'HTML', hint: 'opens in your browser' },
      { value: 'back' as const, label: 'Back' },
    ],
    default: 'pdf' as const,
  });
  if (which === 'back') return;
  const file = path.join(reports, `latest.${which}`);
  if (!(await (deps.openFile ?? openWithSystem)(file))) out.write(`Could not open it from here: ${file}\n`);
  out.write(`The Markdown version is ${path.join(reports, 'latest.md')}\n`);
}

/** Checklist areas that fit the project: websites → surface, auth, input; always secrets; servers or CI files → infra. */
export async function suggestedAreas(dir: string, project: ProjectConfig): Promise<string[]> {
  const ci = (await exists(path.join(dir, '.github', 'workflows'))) || (await exists(path.join(dir, '.gitlab-ci.yml')));
  return [...(project.targets.length > 0 ? ['surface', 'auth', 'input'] : []), 'secrets', ...(project.hosts.length > 0 || ci ? ['infra'] : [])];
}

/** Writes the review checklist for the chosen areas (same text as `secagent checklist`) and says how to work through it. */
export async function exportChecklist(dir: string, deps: WizardDeps): Promise<void> {
  const { prompter, out } = deps;
  const lists = await loadShippedChecklists(await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES));
  const areas = await prompter.multiselect({
    message: 'Which areas fit this project? (I ticked the ones that look relevant)',
    choices: lists.map((l) => ({ value: l.area, label: l.title, hint: `${l.items.length} checks` })),
    initial: await suggestedAreas(dir, await loadProject(dir)),
    min: 1,
  });
  const chosen = selectAreas(lists, areas);
  const file = checklistFile(dir);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, renderChecklist(chosen, await new FindingsStore(dir).latest()), 'utf8');
  const shown = path.relative(dir, file);
  out.write(
    [
      '',
      `I wrote ${chosen.reduce((n, l) => n + l.items.length, 0)} checks to ${shown}: things only someone reading the code can decide.`,
      '',
      'Work through them with:',
      '  • Claude Code:  /security-review',
      `  • Another AI:   "Work through ${shown} against this code. For each item say pass, fail or unknown,`,
      '                   cite file:line, and list the fails first."',
      '  • By hand:      open the file',
      "Those answers are a review, not scan results; the scan's findings do not change.",
      '',
    ].join('\n'),
  );
}

function pickServer(prompter: Prompter, project: ProjectConfig, message: string, suggested?: string): Promise<string> {
  return prompter.select({
    message,
    choices: project.hosts.map((h) => ({ value: h.name, label: h.name, hint: `${h.address} · ${h.env}` })),
    default: suggested ?? project.hosts[0]?.name ?? '',
  });
}

/** Writes the collector on request, then checks and stores its output: the same store `secagent snapshot add` uses. */
export async function addCollectorOutput(dir: string, deps: WizardDeps, suggested?: string): Promise<void> {
  const { prompter, out } = deps;
  const now = nowOf(deps);
  const host = await pickServer(prompter, await loadProject(dir), 'Which server?', suggested);
  if (await prompter.confirm({ message: `Write the read-only collector for ${host} so you can run it on the server?`, default: true })) {
    prompter.note(collectorSteps(await writeCollectorFile(dir, host), host));
  }
  const text = await askSnapshot(prompter, { dir, now, readFile: (file) => readFile(file, 'utf8') }, host);
  if (!text) {
    out.write(`Nothing stored. ${host} stays "not checked" until you add its collector output.\n`);
    return;
  }
  const { snapshot } = await new SnapshotStore(dir, now).add(host, text);
  out.write(`Stored ${host}'s collector output (${snapshot.os.pretty_name || snapshot.os.id}, ${snapshot.packages.length} packages). Scan again so I can check it.\n`);
}

/** A scanner's CVE claim against a server's installed packages: the same call and output as `secagent verify`. */
export async function checkCveClaim(dir: string, deps: WizardDeps): Promise<void> {
  const { prompter, out } = deps;
  const project = await loadProject(dir);
  const name = await pickServer(prompter, project, 'Which server did the scanner report?');
  const cve = (await prompter.text({ message: 'Which CVE? (e.g. CVE-2024-6387)', validate: (v) => (CVE_ID.test(v.trim()) ? undefined : 'Enter an id like CVE-2024-6387') })).trim();
  const pkg = (await prompter.text({ message: 'The package the scanner named (Enter to skip)', default: '' })).trim();
  out.write(`\nLooking up ${cve} in the distro's advisories for ${name}'s installed packages (only package names and versions are sent)...\n`);
  const result = await verifyClaim(
    {
      host: new Scope(project).host(name),
      snapshots: new SnapshotStore(dir, deps.now),
      advisories: deps.advisories ?? createAdvisories(deps.now ? { now: deps.now } : {}),
      evidence: new EvidenceStore(dir, project.network.scan_label, deps.now),
      ...(deps.now ? { now: deps.now } : {}),
    },
    { cve, ...(pkg ? { package: pkg } : {}) },
  );
  out.write(`${formatClaim(result).join('\n')}\n`);
}

/** Lists the accepted risks; true when the person accepted a new one (the caller scans again, as before). */
export async function acceptedRisks(dir: string, deps: WizardDeps): Promise<boolean> {
  const { prompter, out, style } = deps;
  const now = nowOf(deps);
  const { accepted } = await projectStatus(dir, now());
  if (accepted.length === 0) out.write('\nNo accepted risks right now.\n');
  else {
    out.write(`\n${style.bold('Accepted risks')}\n`);
    for (const a of accepted) out.write(`  ${a.findingId}  ${a.owner}: "${a.reason}"  until ${a.expires} (${a.daysLeft === 0 ? 'last day' : `${a.daysLeft} day(s) left`})\n`);
    out.write('  After its date, each counts as open again.\n');
  }
  const input = await loadReportInput(dir);
  const open = input?.record.findings.filter((f) => f.status === 'open') ?? [];
  if (!input || open.length === 0) return false;
  const next = await prompter.select({
    message: 'Accept the risk of a finding?',
    choices: [
      { value: 'accept' as const, label: 'Accept the risk of a finding', hint: `${open.length} open` },
      { value: 'back' as const, label: 'Back' },
    ],
    default: 'back' as const,
  });
  return next === 'accept' && (await acceptFromMenu(dir, input, open, deps, now));
}

export function connectAi(dir: string, deps: WizardDeps): void {
  deps.out.write(`\n${mcpSetupLines(dir).join('\n')}\nIn Claude Code with the secagent plugin you can also type /security-review.\n`);
}

/** What `secagent doctor` checks and prints. */
export async function checkSetup(dir: string, deps: WizardDeps): Promise<void> {
  const { lines } = formatDoctor(await doctor(dir, { now: nowOf(deps), ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}) }));
  deps.out.write(`\n${lines.join('\n')}\n`);
}

export async function showGuides(deps: WizardDeps): Promise<void> {
  const { prompter, out } = deps;
  for (;;) {
    const name = await prompter.select({
      message: 'Which guide?',
      choices: [...GUIDES.map((g) => ({ value: g.name, label: g.title })), { value: '', label: 'Back' }],
      default: GUIDES[0]?.name ?? '',
    });
    const guide = GUIDES.find((g) => g.name === name);
    if (!guide) return;
    out.write(`\n${renderGuide(guide)}\n\n`);
  }
}
