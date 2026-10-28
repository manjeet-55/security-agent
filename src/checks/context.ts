import type { EvidenceStore } from '../evidence/store.js';
import type { HttpObservation } from '../net/http.js';
import { stripBrackets } from '../net/ip.js';
import type { NetClient } from '../net/scoped.js';
import type { Host, ProjectConfig, Target } from '../project/schema.js';
import type { SubjectKind } from '../types.js';

export type CheckSubject = { kind: 'target'; target: Target } | { kind: 'host'; host: Host };

export interface CheckContext {
  project: ProjectConfig;
  net: NetClient;
  evidence: EvidenceStore;
  now: () => Date;
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
