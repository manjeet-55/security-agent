import { describe, expect, it } from 'vitest';
import { suggestNext } from '../../src/home/next.js';
import type { LastScan, ProjectStatus, ServerStatus } from '../../src/home/status.js';

const SCAN: LastScan = { at: '2026-10-28T10:00:00.000Z', ageDays: 1, verdict: { tone: 'green', text: 'No issues found' }, open: [], urgent: 0, unverifiable: 0 };
const SERVER: ServerStatus = { name: 'web-1', address: '203.0.113.10', env: 'prod', collector: 'fresh' };
const RISK = { findingId: 'code-secrets-working-tree@code', owner: 'Priya', reason: 'rotating the key next sprint', expires: '2026-10-31', daysLeft: 3 };

function status(over: Partial<ProjectStatus> = {}): ProjectStatus {
  return { name: 'shop', stack: [], git: true, lastScan: SCAN, websites: [], servers: [], unscanned: [], accepted: [], pendingLessons: 0, checklistExported: true, ...over };
}

describe('suggestNext', () => {
  it('1. never scanned: run the first scan', () => {
    expect(suggestNext(status({ lastScan: undefined }))).toMatchObject({ action: 'scan', text: expect.stringContaining('not been scanned yet') });
  });

  it('2. a server without collector output, or with stale output: add it, naming the server', () => {
    expect(suggestNext(status({ servers: [{ ...SERVER, collector: 'none' }] }))).toMatchObject({ action: 'collector', host: 'web-1', text: expect.stringContaining('web-1 has no collector output yet') });
    expect(suggestNext(status({ servers: [{ ...SERVER, collector: 'stale' }] }))).toMatchObject({ action: 'collector', text: expect.stringContaining('older than 7 days') });
  });

  it('3. open critical or high issues: see what to fix first', () => {
    expect(suggestNext(status({ lastScan: { ...SCAN, urgent: 2 } }))).toMatchObject({ action: 'fixes', text: expect.stringContaining('2 high-priority issue(s)') });
  });

  it('4. an accepted risk ending within 7 days: look at accepted risks', () => {
    expect(suggestNext(status({ accepted: [RISK] }))).toMatchObject({ action: 'risks', text: expect.stringContaining('in 3 day(s)') });
    expect(suggestNext(status({ accepted: [{ ...RISK, daysLeft: 0 }] })).text).toContain('ends today');
    expect(suggestNext(status({ accepted: [{ ...RISK, daysLeft: 8 }] })).action).not.toBe('risks');
  });

  it('5. a site or server the last scan did not reach, or a scan over 7 days old: scan again', () => {
    expect(suggestNext(status({ unscanned: ['https://shop.example.com'] }))).toMatchObject({ action: 'scan', text: expect.stringContaining('https://shop.example.com has not been scanned yet') });
    expect(suggestNext(status({ lastScan: { ...SCAN, ageDays: 8 } }))).toMatchObject({ action: 'scan', text: expect.stringContaining('8 days old') });
  });

  it('6. the checklist was never exported: review what the scan cannot see', () => {
    expect(suggestNext(status({ checklistExported: false })).action).toBe('checklist');
  });

  it('7. otherwise: nothing pressing', () => {
    expect(suggestNext(status())).toMatchObject({ action: 'scan', text: expect.stringContaining('Nothing pressing') });
  });

  it('applies the rules in order: the first match wins', () => {
    expect(suggestNext(status({ servers: [{ ...SERVER, collector: 'none' }], lastScan: { ...SCAN, urgent: 1 } })).action).toBe('collector');
    expect(suggestNext(status({ lastScan: { ...SCAN, urgent: 1 }, accepted: [RISK] })).action).toBe('fixes');
    expect(suggestNext(status({ accepted: [RISK], lastScan: { ...SCAN, ageDays: 30 } })).action).toBe('risks');
    expect(suggestNext(status({ unscanned: ['web-1'], checklistExported: false })).action).toBe('scan');
  });
});
