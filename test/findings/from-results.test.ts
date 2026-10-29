import { describe, expect, it } from 'vitest';
import { CheckInstanceSchema, type CheckInstance } from '../../src/checks/catalog.js';
import { diffScans } from '../../src/findings/diff.js';
import { resultsToFindings } from '../../src/findings/from-results.js';
import type { ScanRecord } from '../../src/findings/schema.js';
import type { RiskException } from '../../src/kb/exceptions.js';
import type { CheckResult, Outcome, Severity } from '../../src/types.js';

const EV = 'ev_20261028T100000Z_00000000';
const NOW = new Date('2026-10-28T11:00:00.000Z');
const inst = CheckInstanceSchema.parse({
  id: 'hdr-hsts', type: 'http_header', title: 'HSTS', severity: 'medium', applies_to: ['web'],
  fix_hints: { nginx: 'add_header ...' }, source_url: 'https://example.com/guide', review: 'approved',
});
const INSTANCES = new Map<string, CheckInstance>([[inst.id, inst]]);
const result = (outcome: Outcome, severity: Severity = 'medium'): CheckResult => ({
  check_id: 'hdr-hsts', target: 'app', title: 'HSTS', outcome, severity, observed: 'seen', evidence_id: EV,
});

describe('resultsToFindings', () => {
  it('maps fail to open with fix, refs and knowledge', () => {
    const [f] = resultsToFindings([result('fail')], INSTANCES, undefined, { proxy: 'nginx' }, NOW);
    expect(f).toMatchObject({
      id: 'hdr-hsts@app', status: 'open', severity: 'medium', evidence: [EV], refs: ['https://example.com/guide'], knowledge: ['hdr-hsts'],
      first_seen: NOW.toISOString(), fix: { where: 'nginx' },
    });
    expect(f?.reasoning).toContain('No AI triage');
    expect(f?.severity_reason).toBeUndefined();
  });

  it('records why severity differs from the instance default', () => {
    const [f] = resultsToFindings([result('fail', 'high')], INSTANCES, undefined, {}, NOW);
    expect(f?.severity_reason).toContain('default medium');
  });

  it('maps unverifiable and error to unverifiable without a fix', () => {
    const findings = resultsToFindings([result('unverifiable'), { ...result('error'), target: 'api' }], INSTANCES, undefined, {}, NOW);
    expect(findings.map((f) => [f.id, f.status, f.fix])).toEqual([
      ['hdr-hsts@app', 'unverifiable', undefined],
      ['hdr-hsts@api', 'unverifiable', undefined],
    ]);
  });

  it('drops passes unless the previous scan had the finding open, then marks it fixed and keeps first_seen', () => {
    expect(resultsToFindings([result('pass')], INSTANCES, undefined, {}, NOW)).toEqual([]);
    const previous = {
      schema: 1, scanned_at: '2026-10-27T10:00:00.000Z', scan_label: 't', mode: 'no-ai', results: [],
      findings: resultsToFindings([result('fail')], INSTANCES, undefined, {}, new Date('2026-10-27T10:00:00.000Z')),
      diff: { new: [], fixed: [], regressed: [] },
    } satisfies ScanRecord;
    const [f] = resultsToFindings([result('pass')], INSTANCES, previous, {}, NOW);
    expect(f).toMatchObject({ status: 'fixed', first_seen: '2026-10-27T10:00:00.000Z', last_seen: NOW.toISOString() });
  });
});

describe('carry-forward of open findings through unverifiable scans', () => {
  const T1 = new Date('2026-10-27T10:00:00.000Z');
  const T2 = new Date('2026-10-28T10:00:00.000Z');
  const T3 = new Date('2026-10-29T10:00:00.000Z');
  const EV2 = 'ev_20261028T100000Z_00000002';
  const EV3 = 'ev_20261029T100000Z_00000003';
  const at = (outcome: Outcome, evidence_id: string, severity: Severity = 'medium'): CheckResult => ({ ...result(outcome, severity), evidence_id });
  const scan = (results: CheckResult[], previous: ScanRecord | undefined, when: Date): ScanRecord => {
    const findings = resultsToFindings(results, INSTANCES, previous, {}, when);
    return { schema: 1, scanned_at: when.toISOString(), scan_label: 't', mode: 'no-ai', results, findings, diff: diffScans(previous, { results, findings }) };
  };
  const first = () => scan([at('fail', EV, 'high')], undefined, T1);

  it.each(['unverifiable', 'error'] as const)('keeps an open finding open when the next scan is %s', (outcome) => {
    const second = scan([at(outcome, EV2)], first(), T2);
    const [f] = second.findings;
    expect(f).toMatchObject({
      status: 'open', severity: 'high', evidence: [EV2, EV], first_seen: T1.toISOString(), last_seen: T1.toISOString(), verified_at: T1.toISOString(),
    });
    expect(f?.reasoning).toContain(`Not re-verified this scan (check outcome: ${outcome}); the previous open status stands.`);
    expect(f?.fix).toBeDefined();
  });

  it('becomes fixed when a pass follows the unverifiable scan', () => {
    const second = scan([at('unverifiable', EV2)], first(), T2);
    const third = scan([at('pass', EV3)], second, T3);
    expect(third.findings[0]?.status).toBe('fixed');
    expect(third.diff.fixed).toEqual(['hdr-hsts@app']);
  });

  it('is not reported as new when a fail follows the unverifiable scan', () => {
    const second = scan([at('unverifiable', EV2)], first(), T2);
    const third = scan([at('fail', EV3, 'high')], second, T3);
    expect(third.diff.new).toEqual([]);
    expect(third.findings[0]).toMatchObject({ status: 'open', first_seen: T1.toISOString(), verified_at: T3.toISOString() });
  });
});

describe('accepted risks (exceptions.yaml)', () => {
  const T1 = new Date('2026-10-27T10:00:00.000Z');
  const ACTIVE: RiskException = { finding_id: 'hdr-hsts@app', owner: 'dev-lead', reason: 'HSTS rolls out with the new proxy', expires: '2026-12-31' };
  const EXPIRED: RiskException = { ...ACTIVE, expires: '2026-10-01' };
  const previousWith = (status: 'open' | 'accepted_risk'): ScanRecord => {
    const [f] = resultsToFindings([result('fail')], INSTANCES, undefined, {}, T1);
    return {
      schema: 1, scanned_at: T1.toISOString(), scan_label: 't', mode: 'no-ai', results: [],
      findings: [{ ...(f as NonNullable<typeof f>), status }], diff: { new: [], fixed: [], regressed: [] },
    };
  };

  it('a failing check with an active exception is an accepted risk that keeps its severity, evidence and fix', () => {
    const [f] = resultsToFindings([result('fail', 'high')], INSTANCES, undefined, { proxy: 'nginx' }, NOW, [ACTIVE]);
    expect(f).toMatchObject({
      id: 'hdr-hsts@app', status: 'accepted_risk', severity: 'high', evidence: [EV],
      exception: { owner: 'dev-lead', reason: 'HSTS rolls out with the new proxy', expires: '2026-12-31', expired: false },
    });
    expect(f?.fix?.where).toBe('nginx');
    expect(f?.reasoning).toContain('Accepted risk');
    expect(f?.reasoning).toContain('dev-lead');
  });

  it('an expired exception leaves the finding open and remembers the earlier decision', () => {
    const [f] = resultsToFindings([result('fail')], INSTANCES, undefined, {}, NOW, [EXPIRED]);
    expect(f).toMatchObject({ status: 'open', exception: { owner: 'dev-lead', expires: '2026-10-01', expired: true } });
  });

  it('an exception only covers the finding it names', () => {
    const findings = resultsToFindings([result('fail'), { ...result('fail'), target: 'api' }], INSTANCES, undefined, {}, NOW, [ACTIVE]);
    expect(findings.map((f) => [f.id, f.status])).toEqual([['hdr-hsts@app', 'accepted_risk'], ['hdr-hsts@api', 'open']]);
  });

  it('cannot accept what could not be checked, and a passing check needs no exception', () => {
    expect(resultsToFindings([result('unverifiable')], INSTANCES, undefined, {}, NOW, [ACTIVE])[0]).toMatchObject({ status: 'unverifiable' });
    expect(resultsToFindings([result('unverifiable')], INSTANCES, undefined, {}, NOW, [ACTIVE])[0]?.exception).toBeUndefined();
    expect(resultsToFindings([result('pass')], INSTANCES, undefined, {}, NOW, [ACTIVE])).toEqual([]);
  });

  it('a finding that was accepted and now passes is fixed, with its first_seen', () => {
    const [f] = resultsToFindings([result('pass')], INSTANCES, previousWith('accepted_risk'), {}, NOW, [ACTIVE]);
    expect(f).toMatchObject({ status: 'fixed', first_seen: T1.toISOString() });
  });

  it('an open finding that is not re-verified becomes accepted when an exception now covers it, and reopens when it lapses', () => {
    expect(resultsToFindings([result('unverifiable')], INSTANCES, previousWith('open'), {}, NOW, [ACTIVE])[0]).toMatchObject({ status: 'accepted_risk' });
    const reopened = resultsToFindings([result('unverifiable')], INSTANCES, previousWith('accepted_risk'), {}, NOW, [EXPIRED])[0];
    expect(reopened).toMatchObject({ status: 'open', exception: { expired: true } });
    expect(reopened?.reasoning).toContain('Not re-verified');
  });
});

