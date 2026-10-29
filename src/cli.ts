#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { defaultCacheDir } from './advisories/cache.js';
import { distroOf } from './advisories/distro.js';
import { createAdvisories } from './advisories/index.js';
import type { Advisories } from './advisories/types.js';
import { CatalogError } from './checks/catalog.js';
import { ObservationError } from './checks/errors.js';
import { distroSources } from './checks/types/host-package.js';
import { EvidenceStore } from './evidence/store.js';
import { resultKey } from './findings/ids.js';
import type { ScanRecord } from './findings/schema.js';
import { makeCollector } from './host/collector.js';
import { SnapshotStore } from './host/store.js';
import { initProject } from './project/init.js';
import { loadProject, ProjectConfigError } from './project/schema.js';
import { Scope, ScopeError } from './project/scope.js';
import { SCAN_GROUPS, scanNoAi, type ScanGroup } from './scan/no-ai.js';
import { SEVERITY_RANK } from './types.js';
import { verifyClaim, type ClaimResult } from './verify/claim.js';

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

const USAGE = `secagent <command> [options]

Commands:
  init    Create .secagent/ in a project, detect its stack, write project.yaml
            --dir <path>           project directory (default: .)
            --name <name>          project name (default: directory name)
            --scan-label <label>   name of the network you scan from, e.g. office
            --target <spec>        id=https://host,web|api,env   (repeatable)
            --host <spec>          name=address,env              (repeatable)
  scan    Run every check against the targets and hosts in project.yaml
            --dir <path>
            --no-ai                deterministic checks only, no AI triage
            --only <groups>        run only code, web or host (repeatable or comma-separated); the rest of the last scan is kept
  collector  Print the read-only host collector script (stdout) and how to run it (stderr)
            --dir <path>   --host <name>   --out <file>
  snapshot add  Validate and store collector output for a host
            --dir <path>   --host <name>   <file>
  verify     Verdict on a scanner's CVE claim for a host, from its snapshot and distro advisories
            --dir <path>   --host <name>   --cve <CVE-id>   [--package <name>]   [--json]
  learn      Refresh CISA KEV and the package advisories for every stored host snapshot
            --dir <path>
`;

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
    options: {
      dir: { type: 'string', default: '.' },
      name: { type: 'string' },
      'scan-label': { type: 'string' },
      target: { type: 'string', multiple: true },
      host: { type: 'string', multiple: true },
    },
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
    options: { dir: { type: 'string', default: '.' }, 'no-ai': { type: 'boolean', default: false }, only: { type: 'string', multiple: true } },
  });
  if (!values['no-ai']) {
    throw new UsageError(
      'AI-triaged scans run inside your AI client through the secagent MCP server. For a deterministic scan without AI, run: secagent scan --no-ai',
    );
  }
  const dir = path.resolve(values.dir);
  const only = parseGroups(values.only ?? []);
  if (only.length === 1 && only[0] === 'code' && !(await loadProject(dir)).code.enabled) {
    throw new UsageError('--only code was asked for, but the code checks are turned off (code.enabled is false in project.yaml)');
  }
  const record = await scanNoAi(dir, {
    ...(only.length > 0 ? { only } : {}),
    ...(deps.now ? { now: deps.now } : {}),
    ...(deps.advisories ? { advisories: deps.advisories } : {}),
  });
  for (const line of formatScan(record)) console.log(line);
  return 0;
}

export interface CliDeps {
  /** Injected advisory sources (tests); defaults to live clients with the user cache. */
  advisories?: Advisories;
  /** Injected clock (tests), used for snapshot age, evidence timestamps and advisory cache expiry; defaults to the wall clock. */
  now?: () => Date;
}

/** `{ now }` when a clock was injected, else nothing (so the callee's default wall clock applies). */
function clockOf(deps: CliDeps): { now?: () => Date } {
  return deps.now ? { now: deps.now } : {};
}

export function formatClaim(r: ClaimResult): string[] {
  return [
    `${r.cve} on ${r.host}: ${r.verdict}${r.kev === true ? ' (CISA KEV: known exploited)' : ''}`,
    `  ${r.reason}`,
    ...r.packages.map(
      (p) => `  ${p.package}: installed ${p.installed ?? '-'}, distro status ${p.distro_status}${p.fixed ? `, fixed in ${p.fixed}` : ''} → ${p.verdict}`,
    ),
    ...(r.source_url ? [`  source: ${r.source_url}`] : []),
    ...(r.as_of ? [`  advisories as of ${r.as_of.slice(0, 10)}${r.stale ? ' (STALE: cached copy, source unreachable)' : ''}`] : []),
    `  evidence: ${r.evidence_id}`,
  ];
}

async function runCollector(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: { dir: { type: 'string', default: '.' }, host: { type: 'string' }, out: { type: 'string' } },
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
    options: { dir: { type: 'string', default: '.' }, host: { type: 'string' } },
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
    options: {
      dir: { type: 'string', default: '.' },
      host: { type: 'string' },
      cve: { type: 'string' },
      package: { type: 'string' },
      json: { type: 'boolean', default: false },
    },
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
  const { values } = parseArgs({ args, strict: true, options: { dir: { type: 'string', default: '.' } } });
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
    const sources = distroSources(stored.snapshot, distro.codename);
    const affected = await advisories.osv.affected(distro.ecosystem, sources);
    for (const q of sources.filter((s) => affected.has(s.name))) await advisories.osv.vulnsFor(distro.ecosystem, q);
    console.log(`${host.name}: ${sources.length} packages checked against ${distro.ecosystem}; ${affected.size} with advisories cached`);
  }
  console.log(`Advisory cache: ${defaultCacheDir()}`);
  return 0;
}

export async function main(argv: readonly string[], deps: CliDeps = {}): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
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
      case undefined:
      case 'help':
      case '--help':
      case '-h':
        console.log(USAGE);
        return 0;
      default:
        console.error(`Unknown command "${command}".\n\n${USAGE}`);
        return 1;
    }
  } catch (e) {
    if (
      e instanceof UsageError ||
      e instanceof ProjectConfigError ||
      e instanceof CatalogError ||
      e instanceof ScopeError ||
      e instanceof ObservationError
    ) {
      console.error(e.message);
      return 1;
    }
    if (e instanceof TypeError && String((e as NodeJS.ErrnoException).code ?? '').startsWith('ERR_PARSE_ARGS')) {
      console.error(`${e.message}\n\n${USAGE}`);
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
