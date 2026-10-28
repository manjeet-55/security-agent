import { describe, expect, it } from 'vitest';
import { evaluateBudget, headerBudgetParams } from '../../../src/checks/types/header-budget.js';
import { fakeObs } from '../../helpers/ctx.js';

const P = headerBudgetParams.parse({});

describe('evaluateBudget', () => {
  it('passes comfortably small headers and reports the margin', () => {
    const v = evaluateBudget(fakeObs({ headerBytes: 1200 }), P);
    expect(v.outcome).toBe('pass');
    expect(v.observed).toContain('2896 bytes below 4096');
  });
  it('fails at the warning level with the instance severity', () => {
    const v = evaluateBudget(fakeObs({ headerBytes: 3974 }), P);
    expect(v.outcome).toBe('fail');
    expect(v.severity).toBeUndefined();
    expect(v.observed).toContain('within 122 bytes');
  });
  it('escalates to high at or over the proxy buffer size', () => {
    expect(evaluateBudget(fakeObs({ headerBytes: 4200 }), P)).toMatchObject({ outcome: 'fail', severity: 'high' });
  });
  it('requires warn_bytes below high_bytes', () => {
    expect(headerBudgetParams.safeParse({ warn_bytes: 5000, high_bytes: 4096 }).success).toBe(false);
  });
});
