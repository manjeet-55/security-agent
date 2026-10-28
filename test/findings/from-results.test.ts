import { describe, expect, it } from 'vitest';
import { CheckInstanceSchema, type CheckInstance } from '../../src/checks/catalog.js';
import { resultsToFindings } from '../../src/findings/from-results.js';
import type { ScanRecord } from '../../src/findings/schema.js';
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
