import { describe, expect, it } from 'vitest';
import { FindingSchema } from '../../src/findings/schema.js';

const base = {
  id: 'hdr-hsts@app',
  check_id: 'hdr-hsts',
  target: 'app',
  severity: 'medium',
  status: 'open',
  title: 'HSTS',
  evidence: ['ev_20261028T100000Z_0a1b2c3d'],
  reasoning: 'missing',
  first_seen: '2026-10-28T10:00:00.000Z',
  last_seen: '2026-10-28T10:00:00.000Z',
  verified_at: '2026-10-28T10:00:00.000Z',
};

describe('FindingSchema', () => {
  it('accepts a finding with evidence and defaults refs/knowledge', () => {
    expect(FindingSchema.parse(base)).toMatchObject({ refs: [], knowledge: [] });
  });
  it('requires at least one evidence id', () => {
    const r = FindingSchema.safeParse({ ...base, evidence: [] });
    expect(r.success).toBe(false);
    expect(JSON.stringify(r.error?.issues)).toContain('at least one evidence id');
  });
  it('rejects anything that is not an evidence id', () => {
    expect(FindingSchema.safeParse({ ...base, evidence: ['trust me'] }).success).toBe(false);
  });
});
