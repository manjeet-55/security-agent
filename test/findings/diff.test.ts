import { describe, expect, it } from 'vitest';
import { diffScans } from '../../src/findings/diff.js';
import type { Finding, ScanRecord } from '../../src/findings/schema.js';
import type { CheckResult, FindingStatus, Outcome } from '../../src/types.js';

const EV = 'ev_20261028T100000Z_00000000';
const T = '2026-10-28T10:00:00.000Z';
const result = (check_id: string, outcome: Outcome): CheckResult => ({ check_id, target: 'app', title: check_id, outcome, severity: 'low', observed: '', evidence_id: EV });
const finding = (check_id: string, status: FindingStatus): Finding => ({
  id: `${check_id}@app`, check_id, target: 'app', severity: 'low', status, title: check_id, evidence: [EV], reasoning: 'r', refs: [], knowledge: [], first_seen: T, last_seen: T, verified_at: T,
});
const record = (results: CheckResult[], findings: Finding[]): ScanRecord => ({
  schema: 1, scanned_at: T, scan_label: 't', mode: 'no-ai', results, findings, diff: { new: [], fixed: [], regressed: [] },
});

describe('diffScans', () => {
  it('treats everything open as new on the first scan', () => {
    expect(diffScans(undefined, { results: [result('a', 'fail')], findings: [finding('a', 'open')] })).toEqual({ new: ['a@app'], fixed: [], regressed: [] });
  });
  it('reports fixed, regressed and unchanged correctly', () => {
    const previous = record(
      [result('a', 'fail'), result('b', 'pass'), result('c', 'fail')],
      [finding('a', 'open'), finding('c', 'open')],
    );
    const current = {
      results: [result('a', 'pass'), result('b', 'fail'), result('c', 'fail')],
      findings: [finding('a', 'fixed'), finding('b', 'open'), finding('c', 'open')],
    };
    expect(diffScans(previous, current)).toEqual({ new: [], fixed: ['a@app'], regressed: ['b@app'] });
  });
});
