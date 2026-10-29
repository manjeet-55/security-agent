import { runGit } from './code/git.js';
import { snapshotFreshness, SnapshotStore } from './host/store.js';
import { FindingsStore } from './findings/store.js';
import { hasConsent } from './project/consent.js';
import { loadProject, ProjectConfigError, projectFile } from './project/schema.js';
import { access } from 'node:fs/promises';

export type DoctorLevel = 'ok' | 'warn' | 'fail';
export interface DoctorLine {
  level: DoctorLevel;
  text: string;
  /** What to do about it, when not ok. */
  fix?: string;
}

export interface DoctorDeps {
  now: () => Date;
  nodeVersion?: string;
  fetchImpl?: typeof fetch;
  /** Skip the network check (offline machines, CI). */
  offline?: boolean;
}

const MIN_NODE = [20, 19, 0] as const;

function nodeAtLeast(version: string): boolean {
  const v = version.split('.').map(Number);
  for (let i = 0; i < 3; i += 1) {
    const need = MIN_NODE[i] ?? 0;
    if ((v[i] ?? 0) !== need) return (v[i] ?? 0) > need;
  }
  return true;
}

/** Checks the things that most often make secagent fail on someone's machine, and says how to fix each. */
export async function doctor(dir: string, deps: DoctorDeps): Promise<DoctorLine[]> {
  const lines: DoctorLine[] = [];
  const node = deps.nodeVersion ?? process.versions.node;
  lines.push(nodeAtLeast(node) ? { level: 'ok', text: `Node ${node}` } : { level: 'fail', text: `Node ${node} is too old`, fix: 'Install Node 20.19 or newer (https://nodejs.org).' });

  const git = await runGit(dir, ['--version']).then((r) => r.code === 0, () => false);
  lines.push(git ? { level: 'ok', text: 'git is installed' } : { level: 'warn', text: 'git was not found', fix: 'Install git: without it the secret-history and .env checks are unverifiable.' });

  let configured = false;
  try {
    await access(projectFile(dir));
    configured = true;
  } catch {
    lines.push({ level: 'warn', text: 'This folder is not set up yet', fix: 'Run: secagent' });
  }
  if (configured) {
    try {
      const p = await loadProject(dir);
      lines.push({ level: 'ok', text: `Project "${p.name}": ${p.targets.length} website(s), ${p.hosts.length} server(s), code checks ${p.code.enabled ? 'on' : 'off'}` });
      if (!(await hasConsent(dir, p))) {
        lines.push({ level: 'warn', text: 'The websites and servers are not confirmed on this machine, so an AI assistant cannot probe them', fix: 'Run `secagent` (or `secagent scan`) here once and confirm.' });
      }
      const store = new SnapshotStore(dir, deps.now);
      for (const h of p.hosts) {
        const stored = await store.latest(h.name).catch(() => undefined);
        if (!stored) {
          lines.push({ level: 'warn', text: `No collector snapshot for server ${h.name}`, fix: `Run: secagent collector --host ${h.name}, run it on the server, then secagent snapshot add --host ${h.name} <file>` });
          continue;
        }
        const { state, ageDays } = snapshotFreshness(stored.snapshot.collected_at, deps.now());
        lines.push(
          state === 'fresh'
            ? { level: 'ok', text: `Snapshot of ${h.name} is ${Math.floor(ageDays)} day(s) old` }
            : { level: 'warn', text: `Snapshot of ${h.name} is ${state === 'stale' ? `${Math.floor(ageDays)} days old` : 'dated in the future'}`, fix: `Collect it again for ${h.name}.` },
        );
      }
      const last = await new FindingsStore(dir).latest();
      lines.push(last ? { level: 'ok', text: `Last scan: ${last.scanned_at.slice(0, 16).replace('T', ' ')} UTC` } : { level: 'warn', text: 'No scan yet', fix: 'Run: secagent scan' });
    } catch (e) {
      if (!(e instanceof ProjectConfigError)) throw e;
      lines.push({ level: 'fail', text: 'project.yaml is not valid', fix: e.message.split('\n').slice(0, 4).join(' ') });
    }
  }

  if (!deps.offline) {
    const doFetch = deps.fetchImpl ?? fetch;
    const reachable = await doFetch('https://api.osv.dev/v1/vulns/GHSA-qw6h-vgh9-j6wx', { signal: AbortSignal.timeout(8000) }).then((r) => r.status < 500, () => false);
    lines.push(reachable ? { level: 'ok', text: 'The advisory database (OSV) is reachable' } : { level: 'warn', text: 'The advisory database (OSV) is not reachable', fix: 'Dependency and server package checks will be unverifiable until it is. Check the proxy or firewall.' });
  }
  return lines;
}
