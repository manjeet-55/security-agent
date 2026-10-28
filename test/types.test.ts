import { describe, expect, it } from 'vitest';
import { maxSeverity, SEVERITY_RANK } from '../src/types.js';

describe('maxSeverity', () => {
  it('returns the most severe entry', () => {
    expect(maxSeverity(['low', 'high', 'medium'])).toBe('high');
  });
  it('returns the fallback for an empty list', () => {
    expect(maxSeverity([])).toBe('info');
    expect(maxSeverity([], 'low')).toBe('low');
  });
  it('ranks critical highest', () => {
    expect(SEVERITY_RANK.critical).toBeGreaterThan(SEVERITY_RANK.high);
  });
});
