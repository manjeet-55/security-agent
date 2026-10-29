import { CheckInstanceSchema, type CheckInstance } from '../../src/checks/catalog.js';
import type { Finding, ScanRecord } from '../../src/findings/schema.js';
import { validateProject, type ProjectConfig } from '../../src/project/schema.js';
import type { CheckResult } from '../../src/types.js';

export const T = '2026-10-28T10:00:00.000Z';
export const EV = (n: number): string => `ev_20261028T100000Z_${n.toString(16).padStart(8, '0')}`;

export function fixtureProject(): ProjectConfig {
  return validateProject({
    version: 1,
    name: 'shop',
    network: { scan_label: 'office' },
    targets: [{ id: 'portal', url: 'https://portal.example.com', type: 'web', env: 'prod' }],
    hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }],
  });
}

function instance(id: string, applies: string[], extra: Record<string, unknown> = {}): CheckInstance {
  return CheckInstanceSchema.parse({
    id,
    type: 'x',
    title: `${id} title`,
    severity: 'medium',
    applies_to: applies,
    fix_hints: { any: `Fix ${id} like this.\nSecond line.` },
    source_url: `https://docs.example.com/${id}`,
    review: 'approved',
    ...extra,
  });
}

export function fixtureInstances(): Map<string, CheckInstance> {
  const list = [
    instance('code-leak', ['code'], { why: 'A leaked key lets anyone use your account.' }),
    instance('code-clean', ['code']),
    instance('hdr-hsts', ['web', 'api']),
    instance('hdr-csp', ['web', 'api']),
    instance('tls-ok', ['web', 'api']),
    instance('ssh-root', ['host']),
    instance('ssh-pass', ['host']),
  ];
  return new Map(list.map((i) => [i.id, i]));
}

function result(check_id: string, target: string, outcome: CheckResult['outcome'], severity: CheckResult['severity'], observed: string, n: number): CheckResult {
  return { check_id, target, title: `${check_id} title`, outcome, severity, observed, evidence_id: EV(n) };
}

function finding(check_id: string, target: string, status: Finding['status'], severity: Finding['severity'], n: number, fix = true): Finding {
  return {
    id: `${check_id}@${target}`,
    check_id,
    target,
    severity,
    status,
    title: `${check_id} title`,
    evidence: [EV(n)],
    reasoning: 'No AI triage (--no-ai).',
    ...(fix ? { fix: { where: 'any', how: `[any] Fix ${check_id} like this.\n[any] Second line.`, side_effects: [] } } : {}),
    refs: [],
    knowledge: [check_id],
    first_seen: T,
    last_seen: T,
    verified_at: T,
  };
}

/** One open high (code), one open medium (web), one unverifiable (host), one fixed (web), a pass in every area. */
export function fixtureRecord(overrides: Partial<ScanRecord> = {}): ScanRecord {
  return {
    schema: 1,
    scanned_at: T,
    scan_label: 'office',
    mode: 'no-ai',
    results: [
      result('code-leak', 'code', 'fail', 'high', '1 potential secret(s) in 1 file(s): src/a.ts:2 aws-access-key-id [1a2b3c4d]', 1),
      result('code-clean', 'code', 'pass', 'medium', 'nothing found', 2),
      result('hdr-hsts', 'portal', 'fail', 'medium', 'Strict-Transport-Security is missing', 3),
      result('hdr-csp', 'portal', 'pass', 'medium', 'CSP | is fine', 4),
      result('tls-ok', 'portal', 'pass', 'medium', 'TLS 1.3', 5),
      result('ssh-root', 'web-1', 'unverifiable', 'medium', 'No collector snapshot for host "web-1". This does not mean the issue is fixed.', 6),
      result('ssh-pass', 'web-1', 'pass', 'medium', 'off', 7),
    ],
    findings: [
      finding('code-leak', 'code', 'open', 'high', 1),
      finding('hdr-hsts', 'portal', 'open', 'medium', 3),
      finding('ssh-root', 'web-1', 'unverifiable', 'medium', 6, false),
      finding('tls-ok', 'portal', 'fixed', 'medium', 5, false),
    ],
    diff: { new: ['code-leak@code'], fixed: ['tls-ok@portal'], regressed: [] },
    ...overrides,
  };
}
