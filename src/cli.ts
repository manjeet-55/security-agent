#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs, type ParseArgsConfig } from 'node:util';
import { defaultCacheDir } from './advisories/cache.js';
import { distroOf } from './advisories/distro.js';
import { createAdvisories } from './advisories/index.js';
import type { Advisories } from './advisories/types.js';
import { CatalogError } from './checks/catalog.js';
import { ObservationError } from './checks/errors.js';
import { distroSources } from './checks/types/host-package.js';
import { EvidenceStore } from './evidence/store.js';
import { resultKey } from './findings/ids.js';
import { FindingsStore } from './findings/store.js';
import type { ScanRecord } from './findings/schema.js';
import { makeCollector } from './host/collector.js';
import { SnapshotStore } from './host/store.js';
import { initProject } from './project/init.js';
import { loadProject, ProjectConfigError } from './project/schema.js';
import { Scope, ScopeError } from './project/scope.js';
import { SCAN_GROUPS, scanNoAi, type ScanGroup } from './scan/no-ai.js';
import { createTtyPrompter, type Prompter } from './ui/prompt.js';
import { createStyle } from './ui/style.js';
import { runWizard } from './wizard/run.js';
import { recordConsent } from './project/consent.js';
import { runMcpStdio } from './mcp/server.js';
import { mcpSetupLines } from './mcp/setup.js';
import { findCommand, type CommandHelp } from './help/commands.js';
import { renderCommand, renderHelp, renderOverview, unknownCommand } from './help/render.js';
import { doctor, formatDoctor } from './doctor.js';
import { evaluate, EvalError } from './eval.js';
import { acceptRisk } from './kb/accept.js';
import { approveLesson, pendingLessons, rejectLesson } from './kb/write.js';
import { loadShippedChecklists, renderChecklist, selectAreas } from './kb/checklist.js';
import { renderIndex } from './kb/index-md.js';
import { KbError } from './kb/lesson.js';
import { loadLessons } from './kb/store.js';
import { loadCheckInstances } from './checks/catalog.js';
import { CHECK_TYPES } from './checks/registry.js';
import { GLOBAL_CHECKS_DIR, GLOBAL_KNOWLEDGE_DIR, GLOBAL_LESSONS_DIR, packageVersion } from './paths.js';
import { SEVERITIES, SEVERITY_RANK, type Severity } from './types.js';
import { verifyClaim } from './verify/claim.js';
import { formatClaim } from './verify/format.js';
import { loadReportInput } from './report/model.js';
import { writeReport, type ReportFormat } from './report/write.js';

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

/** Each command's options, exactly as its parser takes them. `secagent help` documents the same names (test/cli.test.ts checks). */
export const OPTIONS = {
  start: { dir: { type: 'string', default: '.' } },
  init: {
    dir: { type: 'string', default: '.' },
    name: { type: 'string' },
    'scan-label': { type: 'string' },
    target: { type: 'string', multiple: true },
    host: { type: 'string', multiple: true },
  },
  scan: {
    dir: { type: 'string', default: '.' },
    'no-ai': { type: 'boolean', default: false },
    only: { type: 'string', multiple: true },
    'fail-on': { type: 'string' },
  },
  report: { dir: { type: 'string', default: '.' } },
  accept: { dir: { type: 'string', default: '.' }, owner: { type: 'string' }, reason: { type: 'string' }, until: { type: 'string' } },
  checklist: { dir: { type: 'string', default: '.' }, area: { type: 'string', multiple: true }, out: { type: 'string' } },
  collector: { dir: { type: 'string', default: '.' }, host: { type: 'string' }, out: { type: 'string' } },
  'snapshot add': { dir: { type: 'string', default: '.' }, host: { type: 'string' } },
  verify: {
    dir: { type: 'string', default: '.' },
    host: { type: 'string' },
    cve: { type: 'string' },
    package: { type: 'string' },
    json: { type: 'boolean', default: false },
  },
  learn: { dir: { type: 'string', default: '.' } },
  'mcp setup': { dir: { type: 'string', default: '.' } },
  mcp: { dir: { type: 'string', default: '.' } },
  doctor: { dir: { type: 'string', default: '.' }, offline: { type: 'boolean', default: false } },
  eval: { dir: { type: 'string', default: '.' } },
  'kb review': { dir: { type: 'string', default: '.' }, approve: { type: 'string' }, reject: { type: 'string' }, by: { type: 'string' } },
} as const satisfies Record<string, NonNullable<ParseArgsConfig['options']>>;

export function parseTargetSpec(spec: string): { id: string; url: string; type: 'web' | 'api'; env: string } {
  const match = /^([a-z0-9][a-z0-9-]*)=(https?:\/\/[^,]+),(web|api),([^,]+)$/.exec(spec);
  if (!match) throw new UsageError(`--target must look like id=https://host,web|api,env (got "${spec}")`);
  const [, id = '', url = '', type = 'web', env = ''] = match;
  return { id, url, type: type as 'web' | 'api', env };
}

export function parseHostSpec(spec: string): { name: string; address: string; env: string } {
  const match = /^([a-z0-9][a-z0-9-]*)=([^,]+),([^,]+)$/.exec(spec);
  if (!match) throw new UsageError(`--host must look like name=address,env (got "${spec}")`);
  const [, name = '', address = '', env = ''] = match;
  return { name, address, env };
}

export function formatScan(record: ScanRecord): string[] {
  const counts = new Map<string, number>();
  for (const f of record.findings) counts.set(f.status, (counts.get(f.status) ?? 0) + 1);
  const observed = new Map(record.results.map((r) => [resultKey(r), r.observed] as const));
  const lines = [
    `Scan ${record.scanned_at} from network "${record.scan_label}": ${record.results.length} check results, ${record.findings.length} findings`,
    `  ${[...counts].map(([status, n]) => `${status} ${n}`).join(' · ') || 'nothing to report'}`,
  ];
  const sorted = [...record.findings].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id),
  );
  for (const f of sorted) {
    lines.push(`  ${f.severity.toUpperCase().padEnd(8)} ${f.status.padEnd(12)} ${f.id}  ${observed.get(f.id) ?? ''}`);
  }
  lines.push(`Diff vs previous scan: new ${record.diff.new.length}, fixed ${record.diff.fixed.length}, regressed ${record.diff.regressed.length}`);
  lines.push('Details: .secagent/findings/latest.json · evidence: .secagent/evidence/');
  return lines;
}

async function runInit(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: OPTIONS.init,
  });
  const targets = (values.target ?? []).map(parseTargetSpec);
  const hosts = (values.host ?? []).map(parseHostSpec);
  const result = await initProject(path.resolve(values.dir), { name: values.name, scanLabel: values['scan-label'], targets, hosts });

  console.log(result.created ? `Created ${result.stateDir}` : `Updated ${result.stateDir}`);
  if (!result.created && (targets.length > 0 || hosts.length > 0)) {
    console.log('project.yaml already existed: --target/--host were ignored. Edit .secagent/project.yaml to change them.');
  }
  console.log(`Detected stack: ${JSON.stringify(result.config.stack)}`);
  for (const marker of result.detection.markers) console.log(`  ${marker}`);
  if (result.config.targets.length === 0 && result.config.hosts.length === 0) {
    console.log('No targets or hosts yet. Add them to .secagent/project.yaml before scanning.');
  }
  return 0;
}

/** `--only code,web --only host` → [code, web, host]. Anything else is a usage error that names the groups there are. */
function parseGroups(flags: readonly string[]): ScanGroup[] {
  const groups: ScanGroup[] = [];
  for (const name of flags.flatMap((f) => f.split(',')).map((g) => g.trim())) {
    if (!(SCAN_GROUPS as readonly string[]).includes(name)) {
      throw new UsageError(`--only takes ${SCAN_GROUPS.join(', ')} (got "${name}"); repeat the flag or separate groups with commas`);
    }
    if (!groups.includes(name as ScanGroup)) groups.push(name as ScanGroup);
  }
  return groups;
}

async function runScan(args: string[], deps: CliDeps): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: OPTIONS.scan,
  });
  // --no-ai is accepted for older scripts: the scan never uses AI.
  const failOn = values['fail-on'];
  if (failOn !== undefined && !(SEVERITIES as readonly string[]).includes(failOn)) {
    throw new UsageError(`--fail-on takes ${SEVERITIES.join(', ')} (got "${failOn}")`);
  }
  const dir = path.resolve(values.dir);
  const only = parseGroups(values.only ?? []);
  // A person running the scan by hand confirms what project.yaml lists; an AI client over MCP may then probe the same scope.
  await recordConsent(dir, await loadProject(dir), deps.now ? deps.now() : new Date());
  if (only.length === 1 && only[0] === 'code' && !(await loadProject(dir)).code.enabled) {
    throw new UsageError('--only code was asked for, but the code checks are turned off (code.enabled is false in project.yaml)');
  }
  const record = await scanNoAi(dir, {
    trigger: 'cli',
    ...(only.length > 0 ? { only } : {}),
    ...(deps.now ? { now: deps.now } : {}),
    ...(deps.advisories ? { advisories: deps.advisories } : {}),
  });
  for (const line of formatScan(record)) console.log(line);
  await printReport(dir);
  if (failOn) {
    const bad = record.findings.filter((f) => f.status === 'open' && SEVERITY_RANK[f.severity] >= SEVERITY_RANK[failOn as Severity]);
    if (bad.length > 0) {
      console.error(`Failing: ${bad.length} open finding(s) at ${failOn} or above (--fail-on ${failOn}).`);
      return 1;
    }
  }
  return 0;
}

const REPORT_FORMATS: readonly ReportFormat[] = ['md', 'pdf', 'html'];

/** Writes the report of the latest scan and prints where it is. */
async function printReport(dir: string): Promise<void> {
  const input = await loadReportInput(dir);
  if (!input) throw new UsageError('No scan yet: run secagent scan first');
  const { latest } = await writeReport(dir, input, { formats: REPORT_FORMATS });
  for (const file of latest) console.log(`Report: ${file}`);
}

async function runAccept(args: string[], deps: CliDeps): Promise<number> {
  const usage = 'Usage: secagent accept <finding-id> --owner <name> --reason <text> --until <YYYY-MM-DD> [--dir <path>]';
  const { values, positionals } = parseArgs({
    args,
    strict: true,
    allowPositionals: true,
    options: OPTIONS.accept,
  });
  const [findingId] = positionals;
  if (!findingId || positionals.length !== 1 || !values.owner || !values.reason || !values.until) throw new UsageError(usage);
  const entry = await acceptRisk(path.resolve(values.dir), { findingId, owner: values.owner, reason: values.reason, until: values.until }, deps.now ? deps.now() : new Date());
  console.log(`Accepted ${entry.finding_id} until ${entry.expires} (${entry.owner}). Scan again to update the report; it will list this under Accepted risks, and it counts as open again after that date.`);
  return 0;
}

async function runEval(args: string[]): Promise<number> {
  const { values, positionals } = parseArgs({ args, strict: true, allowPositionals: true, options: OPTIONS.eval });
  if (positionals.length !== 1) throw new UsageError('Usage: secagent eval <expected.yaml> [--dir <path>]');
  const rows = await evaluate(path.resolve(values.dir), path.resolve(positionals[0] as string));
  for (const r of rows) console.log(`${r.ok ? 'ok  ' : 'DIFF'}  ${r.id}  expected ${r.expected.join(' or ')}, got ${r.actual}`);
  const bad = rows.filter((r) => !r.ok).length;
  console.log(`${rows.length - bad} of ${rows.length} as expected`);
  return bad === 0 ? 0 : 1;
}

async function runKbReview(args: string[], deps: CliDeps): Promise<number> {
  const { values } = parseArgs({ args, strict: true, options: OPTIONS['kb review'] });
  const dir = path.resolve(values.dir);
  const now = deps.now ? deps.now() : new Date();
  if (values.approve) {
    if (!values.by) throw new UsageError('Usage: secagent kb review --approve <id> --by <name>');
    const l = await approveLesson(dir, values.approve, values.by, now);
    console.log(`Approved ${l.id} (${values.by}). It can now back lowering a risk.`);
    return 0;
  }
  if (values.reject) {
    await rejectLesson(dir, values.reject);
    console.log(`Rejected and removed ${values.reject}.`);
    return 0;
  }
  const pending = await pendingLessons(dir);
  if (pending.length === 0) {
    console.log('No pending lessons.');
    return 0;
  }
  for (const l of pending) {
    console.log(`${l.id}: ${l.title}`);
    console.log(`  source: ${l.source_url ?? '-'}`);
    console.log(`  quote:  "${l.quote ?? ''}"`);
    console.log(`  ${l.body.split('\n')[0]?.slice(0, 200) ?? ''}`);
  }
  console.log(`\nApprove: secagent kb review --approve <id> --by <your name>    Reject: secagent kb review --reject <id>`);
  return 0;
}

async function runKb(args: string[], deps: CliDeps): Promise<number> {
  if (args[0] === 'review') return runKbReview(args.slice(1), deps);
  if (args.length !== 1 || args[0] !== 'index') throw new UsageError('Usage: secagent kb index | secagent kb review');
  const checks = await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES);
  const text = renderIndex(await loadLessons({ global: GLOBAL_LESSONS_DIR }), checks, await loadShippedChecklists(checks));
  const file = path.join(GLOBAL_KNOWLEDGE_DIR, 'INDEX.md');
  await writeFile(file, text, 'utf8');
  console.log(`Wrote ${file}`);
  return 0;
}

/** The review checklist as Markdown, with the latest scan's outcomes for its automated items. */
async function runChecklist(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: OPTIONS.checklist,
  });
  const areas = (values.area ?? []).flatMap((a) => a.split(',')).map((a) => a.trim()).filter(Boolean);
  const lists = selectAreas(await loadShippedChecklists(await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES)), areas);
  const text = renderChecklist(lists, await new FindingsStore(path.resolve(values.dir)).latest());
  if (!values.out) {
    console.log(text.trimEnd());
    return 0;
  }
  await writeFile(path.resolve(values.out), text, 'utf8');
  console.log(`Wrote ${values.out}: ${lists.reduce((n, l) => n + l.items.length, 0)} item(s) in ${lists.length} area(s). Work through it by hand or give it to an AI assistant that can read the code.`);
  return 0;
}

async function runDoctor(args: string[], deps: CliDeps): Promise<number> {
  const { values } = parseArgs({ args, strict: true, options: OPTIONS.doctor });
  const { lines, code } = formatDoctor(await doctor(path.resolve(values.dir), { now: deps.now ?? (() => new Date()), offline: values.offline }));
  for (const line of lines) console.log(line);
  return code;
}

function mcpSetup(args: string[]): number {
  const { values } = parseArgs({ args, strict: true, options: OPTIONS['mcp setup'] });
  for (const line of mcpSetupLines(path.resolve(values.dir))) console.log(line);
  return 0;
}

async function runMcp(args: string[], deps: CliDeps): Promise<number> {
  if (args[0] === 'setup') return mcpSetup(args.slice(1));
  const { values } = parseArgs({ args, strict: true, options: OPTIONS.mcp });
  const dir = path.resolve(values.dir);
  await loadProject(dir);
  await runMcpStdio({ projectDir: dir, ...clockOf(deps), ...(deps.advisories ? { advisories: deps.advisories } : {}) });
  return 0;
}

async function runReport(args: string[]): Promise<number> {
  const { values } = parseArgs({ args, strict: true, options: OPTIONS.report });
  await printReport(path.resolve(values.dir));
  return 0;
}

export interface CliDeps {
  /** Whether stdin and stdout are a terminal (tests); defaults to the real streams. */
  tty?: boolean;
  /** Answers for the guided scan (tests); defaults to prompts on the terminal. */
  prompter?: Prompter;
  /** Where the guided scan prints (tests); defaults to stdout. */
  out?: NodeJS.WritableStream;
  /** Injected advisory sources (tests); defaults to live clients with the user cache. */
  advisories?: Advisories;
  /** Injected clock (tests), used for snapshot age, evidence timestamps and advisory cache expiry; defaults to the wall clock. */
  now?: () => Date;
}

/** `{ now }` when a clock was injected, else nothing (so the callee's default wall clock applies). */
function clockOf(deps: CliDeps): { now?: () => Date } {
  return deps.now ? { now: deps.now } : {};
}

async function runCollector(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: OPTIONS.collector,
  });
  const dir = path.resolve(values.dir);
  if (values.host) new Scope(await loadProject(dir)).host(values.host);
  const bundle = await makeCollector(dir, values.host ?? 'HOST');
  if (values.out) {
    await writeFile(values.out, bundle.script, 'utf8');
    console.error(`Wrote ${values.out}`);
  } else {
    process.stdout.write(bundle.script);
  }
  console.error(bundle.instructions);
  return 0;
}

async function runSnapshot(args: string[], deps: CliDeps): Promise<number> {
  const [sub, ...rest] = args;
  const usage = 'Usage: secagent snapshot add --host <name> [--dir <path>] <file>';
  if (sub !== 'add') throw new UsageError(usage);
  const { values, positionals } = parseArgs({
    args: rest,
    strict: true,
    allowPositionals: true,
    options: OPTIONS['snapshot add'],
  });
  const file = positionals[0];
  if (!values.host || !file) throw new UsageError(usage);
  const dir = path.resolve(values.dir);
  new Scope(await loadProject(dir)).host(values.host);
  const { snapshot, file: stored } = await new SnapshotStore(dir, deps.now).add(values.host, await readFile(path.resolve(file), 'utf8'));
  const rootNote = snapshot.is_root ? '' : ' (not run as root: sshd/nginx sections may be unreadable)';
  console.log(`Stored ${stored}: ${snapshot.os.pretty_name || snapshot.os.id}, ${snapshot.packages.length} packages, collected ${snapshot.collected_at}${rootNote}`);
  return 0;
}

async function runVerify(args: string[], deps: CliDeps): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: OPTIONS.verify,
  });
  if (!values.host || !values.cve) throw new UsageError('Usage: secagent verify --host <name> --cve <CVE-id> [--package <name>] [--dir <path>] [--json]');
  if (!/^CVE-\d{4}-\d{4,}$/i.test(values.cve.trim())) throw new UsageError(`--cve must look like CVE-2024-6387 (got "${values.cve}")`);
  const dir = path.resolve(values.dir);
  const project = await loadProject(dir);
  const host = new Scope(project).host(values.host);
  const result = await verifyClaim(
    {
      host,
      snapshots: new SnapshotStore(dir, deps.now),
      advisories: deps.advisories ?? createAdvisories(clockOf(deps)),
      evidence: new EvidenceStore(dir, project.network.scan_label, deps.now),
      ...clockOf(deps),
    },
    { cve: values.cve, ...(values.package ? { package: values.package } : {}) },
  );
  if (values.json) console.log(JSON.stringify(result, null, 2));
  else for (const line of formatClaim(result)) console.log(line);
  return 0;
}

async function runLearn(args: string[], deps: CliDeps): Promise<number> {
  const { values } = parseArgs({ args, strict: true, options: OPTIONS.learn });
  const dir = path.resolve(values.dir);
  const project = await loadProject(dir);
  const advisories = deps.advisories ?? createAdvisories(clockOf(deps));
  const store = new SnapshotStore(dir, deps.now);
  console.log(`CISA KEV: ${(await advisories.kev.catalog()).size} known-exploited CVEs cached`);
  for (const host of project.hosts) {
    const stored = await store.latest(host.name);
    if (!stored) {
      console.log(`${host.name}: no snapshot, skipped`);
      continue;
    }
    const distro = distroOf(stored.snapshot.os);
    if (!distro) {
      console.log(`${host.name}: ${stored.snapshot.os.id || 'unknown OS'} is not supported, skipped`);
      continue;
    }
    const sources = distroSources(stored.snapshot, distro.codename, host.distro_mirrors);
    const affected = await advisories.osv.affected(distro.ecosystem, sources);
    for (const q of sources.filter((s) => affected.has(s.name))) await advisories.osv.vulnsFor(distro.ecosystem, q);
    console.log(`${host.name}: ${sources.length} packages checked against ${distro.ecosystem}; ${affected.size} with advisories cached`);
  }
  console.log(`Advisory cache: ${defaultCacheDir()}`);
  return 0;
}

/** The guided scan, on the terminal unless a prompter was injected. */
async function runStart(args: string[], deps: CliDeps): Promise<number> {
  const { values } = parseArgs({ args, strict: true, options: OPTIONS.start });
  const out = deps.out ?? process.stdout;
  const style = createStyle(out as { isTTY?: boolean });
  const dir = path.resolve(values.dir);
  if (deps.prompter) return runWizard(dir, { prompter: deps.prompter, out, style, ...(deps.now ? { now: deps.now } : {}), ...(deps.advisories ? { advisories: deps.advisories } : {}) });
  const prompter = createTtyPrompter(process.stdin, out, style);
  try {
    return await runWizard(dir, { prompter, out, style, ...(deps.now ? { now: deps.now } : {}), ...(deps.advisories ? { advisories: deps.advisories } : {}) });
  } finally {
    prompter.close();
  }
}

function isTerminal(deps: CliDeps): boolean {
  return deps.tty ?? Boolean(process.stdin.isTTY && process.stdout.isTTY);
}

/** The page for `secagent <command> [sub-command] ...`: words before the options name it. */
function pageFor(command: string, rest: readonly string[]): CommandHelp | undefined {
  return findCommand([command, ...rest.filter((a) => !a.startsWith('-'))]);
}

/** Where to read more after a usage error: the command's page, and for a bad option its usage line too. */
function helpHint(command: string, rest: readonly string[], withUsage: boolean): string {
  const page = pageFor(command, rest);
  if (!page) return 'Run secagent help to see every command.';
  return `${withUsage ? `Usage: ${page.usage}\n` : ''}Run secagent help ${page.name} for details.`;
}

function runHelp(words: readonly string[]): number {
  const { ok, text } = renderHelp(words);
  if (ok) console.log(text);
  else console.error(text);
  return ok ? 0 : 1;
}

export async function main(argv: readonly string[], deps: CliDeps = {}): Promise<number> {
  const [command, ...rest] = argv;
  try {
    // `<command> --help` shows that command's page and runs nothing.
    if (command !== undefined && (rest.includes('--help') || rest.includes('-h'))) {
      const page = pageFor(command, rest);
      if (page) {
        console.log(renderCommand(page));
        return 0;
      }
    }
    switch (command) {
      case 'start':
        if (!isTerminal(deps)) throw new UsageError('secagent start needs an interactive terminal. In scripts, use secagent init and secagent scan.');
        return await runStart(rest, deps);
      case 'init':
        return await runInit(rest);
      case 'scan':
        return await runScan(rest, deps);
      case 'collector':
        return await runCollector(rest);
      case 'snapshot':
        return await runSnapshot(rest, deps);
      case 'verify':
        return await runVerify(rest, deps);
      case 'learn':
        return await runLearn(rest, deps);
      case 'report':
        return await runReport(rest);
      case 'mcp':
        return await runMcp(rest, deps);
      case 'kb':
        return await runKb(rest, deps);
      case 'accept':
        return await runAccept(rest, deps);
      case 'doctor':
        return await runDoctor(rest, deps);
      case 'eval':
        return await runEval(rest);
      case 'checklist':
        return await runChecklist(rest);
      case undefined:
        if (isTerminal(deps)) return await runStart(rest, deps);
        console.log(renderOverview());
        return 0;
      case '--version':
      case '-v':
      case 'version':
        console.log(`secagent ${packageVersion()}`);
        return 0;
      case 'help':
      case '--help':
      case '-h':
        return runHelp(rest);
      default:
        console.error(unknownCommand(command));
        return 1;
    }
  } catch (e) {
    if (
      e instanceof UsageError ||
      e instanceof ProjectConfigError ||
      e instanceof CatalogError ||
      e instanceof ScopeError ||
      e instanceof KbError ||
      e instanceof EvalError ||
      e instanceof ObservationError
    ) {
      console.error(e.message);
      if (e instanceof UsageError && command !== undefined) console.error(helpHint(command, rest, false));
      return 1;
    }
    if (e instanceof TypeError && String((e as NodeJS.ErrnoException).code ?? '').startsWith('ERR_PARSE_ARGS')) {
      console.error(e.message);
      if (command !== undefined) console.error(helpHint(command, rest, true));
      return 1;
    }
    throw e;
  }
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(realpathSync(invokedPath)).href) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (e: unknown) => {
      console.error(e);
      process.exitCode = 2;
    },
  );
}
