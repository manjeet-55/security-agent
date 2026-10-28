#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { CatalogError } from './checks/catalog.js';
import { resultKey } from './findings/ids.js';
import type { ScanRecord } from './findings/schema.js';
import { initProject } from './project/init.js';
import { ProjectConfigError } from './project/schema.js';
import { scanNoAi } from './scan/no-ai.js';
import { SEVERITY_RANK } from './types.js';

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

async function runScan(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: { dir: { type: 'string', default: '.' }, 'no-ai': { type: 'boolean', default: false } },
  });
  if (!values['no-ai']) {
    throw new UsageError(
      'AI-triaged scans run inside your AI client through the secagent MCP server. For a deterministic scan without AI, run: secagent scan --no-ai',
    );
  }
  const record = await scanNoAi(path.resolve(values.dir));
  for (const line of formatScan(record)) console.log(line);
  return 0;
}

export async function main(argv: readonly string[]): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
      case 'init':
        return await runInit(rest);
      case 'scan':
        return await runScan(rest);
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
    if (e instanceof UsageError || e instanceof ProjectConfigError || e instanceof CatalogError) {
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
