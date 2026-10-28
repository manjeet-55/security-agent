import { describe, expect, it } from 'vitest';
import { EVIDENCE_ID_PATTERN, EvidenceStore, newEvidenceId } from '../../src/evidence/store.js';
import { tempDir } from '../helpers/tmp.js';

describe('EvidenceStore', () => {
  it('formats ids from the capture time', () => {
    const id = newEvidenceId(new Date('2026-10-28T10:15:00.123Z'));
    expect(id).toMatch(/^ev_20261028T101500Z_[0-9a-f]{8}$/);
    expect(EVIDENCE_ID_PATTERN.test(id)).toBe(true);
  });

  it('round-trips a record with scan label and timestamp', async () => {
    const dir = await tempDir();
    const store = new EvidenceStore(dir, 'office', () => new Date('2026-10-28T10:00:00.000Z'));
    const id = await store.put('http', 'app', 'GET / → 200', { status: 200 });
    expect(await store.get(id)).toEqual({
      id,
      kind: 'http',
      target: 'app',
      scan_label: 'office',
      captured_at: '2026-10-28T10:00:00.000Z',
      summary: 'GET / → 200',
      data: { status: 200 },
    });
  });

  it('rejects ids that are not evidence ids (no path traversal)', async () => {
    const store = new EvidenceStore(await tempDir(), 'office');
    await expect(store.get('../../etc/passwd')).rejects.toThrow(/Invalid evidence id/);
  });
});
