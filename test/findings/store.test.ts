import { readdirSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ScanRecord } from '../../src/findings/schema.js';
import { FindingsStore } from '../../src/findings/store.js';
import { tempDir } from '../helpers/tmp.js';

const record = (scanned_at: string): ScanRecord => ({
  schema: 1, scanned_at, scan_label: 'office', mode: 'no-ai', results: [], findings: [], diff: { new: [], fixed: [], regressed: [] },
});

describe('FindingsStore', () => {
  it('returns undefined before the first scan', async () => {
    expect(await new FindingsStore(await tempDir()).latest()).toBeUndefined();
  });
  it('writes latest.json and one history file per scan', async () => {
    const dir = await tempDir();
    const store = new FindingsStore(dir);
    await store.write(record('2026-10-28T10:00:00.000Z'));
    await store.write(record('2026-10-28T10:05:00.000Z'));
    expect((await store.latest())?.scanned_at).toBe('2026-10-28T10:05:00.000Z');
    expect(readdirSync(path.join(dir, '.secagent', 'findings', 'history')).sort()).toEqual([
      '20261028T100000.000Z.json',
      '20261028T100500.000Z.json',
    ]);
  });
  it('refuses to write an invalid record', async () => {
    const bad = { ...record('2026-10-28T10:00:00.000Z'), scan_label: 42 } as unknown as ScanRecord;
    await expect(new FindingsStore(await tempDir()).write(bad)).rejects.toThrow();
  });
});
