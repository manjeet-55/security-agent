import { access } from 'node:fs/promises';
import path from 'node:path';
import { repoState } from '../code/git.js';
import { FindingsStore } from '../findings/store.js';
import { snapshotFreshness, SnapshotStore } from '../host/store.js';
import { loadExceptions } from '../kb/exceptions.js';
import { pendingLessons } from '../kb/write.js';
import { projectStateDir } from '../paths.js';
import { loadProject } from '../project/schema.js';
import { verdict, type Tone } from '../report/model.js';
import { SEVERITIES, type Severity } from '../types.js';

const DAY_MS = 86_400_000;

export interface LastScan {
  at: string;
  /** Whole days since the scan. */
  ageDays: number;
  verdict: { tone: Tone; text: string };
  /** Open findings per severity, most severe first; severities with none are left out. */
  open: Array<[Severity, number]>;
  /** Open critical and high findings. */
  urgent: number;
  /** Findings that could not be checked. */
  unverifiable: number;
}

export interface ServerStatus {
  name: string;
  address: string;
  env: string;
  /** The stored collector output: none, fresh, or stale (older than 7 days). */
  collector: 'none' | 'fresh' | 'stale';
}

export interface AcceptedRisk {
  findingId: string;
  owner: string;
  reason: string;
  expires: string;
  /** Days until the last day it holds; 0 on that day. */
  daysLeft: number;
}

export interface ProjectStatus {
  name: string;
  stack: string[];
  git: boolean;
  lastScan?: LastScan;
  websites: Array<{ id: string; url: string; env: string }>;
  servers: ServerStatus[];
  /** Websites (by URL) and servers (by name) in project.yaml with no result in the last scan. */
  unscanned: string[];
  /** Accepted risks in force today, the soonest to end first. */
  accepted: AcceptedRisk[];
  pendingLessons: number;
  checklistExported: boolean;
}

/** Where the home screen writes the review checklist (reports/ is git-ignored). */
export function checklistFile(dir: string): string {
  return path.join(projectStateDir(dir), 'reports', 'checklist.md');
}

async function exists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

/** Where the project stands, from local files only: no network, nothing written. */
export async function projectStatus(dir: string, now: Date): Promise<ProjectStatus> {
  const project = await loadProject(dir);
  const record = await new FindingsStore(dir).latest();
  const store = new SnapshotStore(dir, () => now);
  const servers: ServerStatus[] = [];
  for (const h of project.hosts) {
    // A host with only future-dated output throws; that output cannot be used, so it counts as none.
    const stored = await store.latest(h.name).catch(() => undefined);
    const collector = !stored ? 'none' : snapshotFreshness(stored.snapshot.collected_at, now).state === 'stale' ? 'stale' : 'fresh';
    servers.push({ name: h.name, address: h.address, env: h.env, collector });
  }

  let lastScan: LastScan | undefined;
  if (record) {
    const open = record.findings.filter((f) => f.status === 'open');
    lastScan = {
      at: record.scanned_at,
      ageDays: Math.max(0, Math.floor((now.getTime() - Date.parse(record.scanned_at)) / DAY_MS)),
      verdict: verdict(record),
      open: SEVERITIES.map((s) => [s, open.filter((f) => f.severity === s).length] as [Severity, number]).filter(([, n]) => n > 0),
      urgent: open.filter((f) => f.severity === 'critical' || f.severity === 'high').length,
      unverifiable: record.findings.filter((f) => f.status === 'unverifiable').length,
    };
  }
  const reached = new Set(record?.results.map((r) => r.target) ?? []);
  const unscanned = record
    ? [...project.targets.filter((t) => !reached.has(t.id)).map((t) => t.url), ...project.hosts.filter((h) => !reached.has(h.name)).map((h) => h.name)]
    : [];

  const today = now.toISOString().slice(0, 10);
  const accepted = (await loadExceptions(dir))
    .filter((x) => today <= x.expires)
    .map((x) => ({ findingId: x.finding_id, owner: x.owner, reason: x.reason, expires: x.expires, daysLeft: Math.round((Date.parse(x.expires) - Date.parse(today)) / DAY_MS) }))
    .sort((a, b) => a.expires.localeCompare(b.expires) || a.findingId.localeCompare(b.findingId));

  return {
    name: project.name,
    stack: Object.values(project.stack).filter((v): v is string => typeof v === 'string'),
    git: (await repoState(dir)).state === 'repo',
    ...(lastScan ? { lastScan } : {}),
    websites: project.targets.map((t) => ({ id: t.id, url: t.url, env: t.env })),
    servers,
    unscanned,
    accepted,
    pendingLessons: (await pendingLessons(dir).catch(() => [])).length,
    checklistExported: await exists(checklistFile(dir)),
  };
}
