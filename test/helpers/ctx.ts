import type { Advisories } from '../../src/advisories/types.js';
import type { CheckContext, CheckSubject } from '../../src/checks/context.js';
import { EvidenceStore } from '../../src/evidence/store.js';
import type { SnapshotReader } from '../../src/host/store.js';
import type { HttpObservation } from '../../src/net/http.js';
import type { NetClient } from '../../src/net/scoped.js';
import { validateProject } from '../../src/project/schema.js';
import { tempDir } from './tmp.js';

export const FIXED_NOW = new Date('2026-10-28T15:00:00.000Z');

export function fakeObs(partial: Partial<HttpObservation> = {}): HttpObservation {
  return {
    url: 'https://app.example.com/',
    status: 200,
    headers: {},
    setCookies: [],
    headerBytes: 200,
    bodySnippet: '',
    bodyBytes: 0,
    ...partial,
  };
}

const unstubbed = (name: string) => async (): Promise<never> => {
  throw new Error(`net.${name} was not stubbed in this test`);
};

export const NO_SNAPSHOTS: SnapshotReader = { latest: async () => undefined };

const unstubbedAdvisory = async (): Promise<never> => {
  throw new Error('advisories were not stubbed in this test');
};
export const NO_ADVISORIES: Advisories = {
  osv: { affected: unstubbedAdvisory, vulnsFor: unstubbedAdvisory, vuln: unstubbedAdvisory },
  ubuntu: { cve: unstubbedAdvisory },
  kev: { catalog: unstubbedAdvisory },
  track: async (fn) => ({ value: await fn(), freshness: undefined }),
};

/** A context with one web target "app" (https://app.example.com) and one host "web-1" (203.0.113.10). */
export async function makeCtx(
  net: Partial<NetClient> = {},
  projectOverrides: Record<string, unknown> = {},
  deps: { snapshots?: SnapshotReader; advisories?: Advisories } = {},
): Promise<{ ctx: CheckContext; dir: string }> {
  const dir = await tempDir();
  const project = validateProject({
    version: 1,
    name: 'test',
    network: { scan_label: 'test-net' },
    targets: [{ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' }],
    hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod', reachable_from: ['office'] }],
    ...projectOverrides,
  });
  const ctx: CheckContext = {
    project,
    net: { http: unstubbed('http'), tls: unstubbed('tls'), tcp: unstubbed('tcp'), ...net },
    evidence: new EvidenceStore(dir, project.network.scan_label, () => FIXED_NOW),
    now: () => FIXED_NOW,
    snapshots: deps.snapshots ?? NO_SNAPSHOTS,
    advisories: deps.advisories ?? NO_ADVISORIES,
    memo: new Map(),
  };
  return { ctx, dir };
}

export function targetSubject(ctx: CheckContext): Extract<CheckSubject, { kind: 'target' }> {
  const target = ctx.project.targets[0];
  if (!target) throw new Error('test project has no target');
  return { kind: 'target', target };
}

export function codeSubject(dir: string): Extract<CheckSubject, { kind: 'code' }> {
  return { kind: 'code', dir };
}

export function hostSubject(ctx: CheckContext): Extract<CheckSubject, { kind: 'host' }> {
  const host = ctx.project.hosts[0];
  if (!host) throw new Error('test project has no host');
  return { kind: 'host', host };
}
