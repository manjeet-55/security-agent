import type { Advisories } from '../advisories/types.js';
import type { EvidenceStore } from '../evidence/store.js';
import { MAX_SNAPSHOT_AGE_DAYS, type SnapshotReader, type StoredSnapshot } from '../host/store.js';
import type { HttpObservation } from '../net/http.js';
import { stripBrackets } from '../net/ip.js';
import type { NetClient } from '../net/scoped.js';
import type { Host, ProjectConfig, Target } from '../project/schema.js';
import type { SubjectKind } from '../types.js';
import { ObservationError } from './errors.js';

export type CheckSubject = { kind: 'target'; target: Target } | { kind: 'host'; host: Host };

export interface CheckContext {
  project: ProjectConfig;
  net: NetClient;
  evidence: EvidenceStore;
  now: () => Date;
  /** Collector snapshots for host checks. */
  snapshots: SnapshotReader;
  /** Distro advisory sources (OSV, Ubuntu, CISA KEV). */
  advisories: Advisories;
  /** Per-scan cache so checks sharing an observation (e.g. the target's page) fetch it once. */
  memo: Map<string, Promise<unknown>>;
}

export function subjectId(subject: CheckSubject): string {
  return subject.kind === 'target' ? subject.target.id : subject.host.name;
}

export function subjectKind(subject: CheckSubject): SubjectKind {
  return subject.kind === 'target' ? subject.target.type : 'host';
}

/** Hostname or address that network probes for this subject go to. */
export function subjectHostname(subject: CheckSubject): string {
  return subject.kind === 'target' ? stripBrackets(new URL(subject.target.url).hostname) : subject.host.address;
}

export function memoize<T>(ctx: CheckContext, key: string, fn: () => Promise<T>): Promise<T> {
  let pending = ctx.memo.get(key) as Promise<T> | undefined;
  if (!pending) {
    pending = fn();
    ctx.memo.set(key, pending);
  }
  return pending;
}

export interface Page {
  obs: HttpObservation;
  evidenceId: string;
}

/** GET a target URL once per scan; header, cookie and budget checks share the observation and its evidence. */
export function getPage(
  ctx: CheckContext,
  subject: Extract<CheckSubject, { kind: 'target' }>,
  url: string = subject.target.url,
): Promise<Page> {
  return memoize(ctx, `GET ${url}`, async () => {
    const obs = await ctx.net.http(url);
    const evidenceId = await ctx.evidence.put('http', subject.target.id, `GET ${url} → ${obs.status}`, obs);
    return { obs, evidenceId };
  });
}

/** The newest snapshot for a host, once per scan. Missing or older than MAX_SNAPSHOT_AGE_DAYS → ObservationError (unverifiable). */
export function getSnapshot(ctx: CheckContext, host: Host): Promise<StoredSnapshot> {
  return memoize(ctx, `SNAPSHOT ${host.name}`, async () => {
    const stored = await ctx.snapshots.latest(host.name);
    if (!stored) {
      throw new ObservationError(
        'NO_SNAPSHOT',
        `No collector snapshot for host "${host.name}". Run "secagent collector --host ${host.name}", run it on the host, then "secagent snapshot add --host ${host.name} <file>".`,
      );
    }
    const ageDays = (ctx.now().getTime() - Date.parse(stored.snapshot.collected_at)) / 86_400_000;
    if (ageDays > MAX_SNAPSHOT_AGE_DAYS) {
      throw new ObservationError(
        'SNAPSHOT_STALE',
        `The newest snapshot for host "${host.name}" is ${Math.floor(ageDays)} days old (limit ${MAX_SNAPSHOT_AGE_DAYS}). Re-run the collector.`,
      );
    }
    return stored;
  });
}
