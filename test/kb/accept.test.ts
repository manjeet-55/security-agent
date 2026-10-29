import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FindingsStore } from '../../src/findings/store.js';
import { acceptRisk } from '../../src/kb/accept.js';
import { loadExceptions } from '../../src/kb/exceptions.js';
import { KbError } from '../../src/kb/lesson.js';
import { FIXED_NOW } from '../helpers/ctx.js';
import { makeProject } from '../helpers/project.js';
import { writeFiles } from '../helpers/tmp.js';
import { fixtureRecord } from '../report/fixture.js';

const NOW = new Date('2026-10-28T12:00:00.000Z');
const OK = { findingId: 'hdr-hsts@portal', owner: 'dev-lead', reason: 'HSTS rolls out with the new proxy', until: '2026-12-31' };

async function projectWithScan() {
  const dir = await makeProject();
  await new FindingsStore(dir).write(fixtureRecord());
  return dir;
}

describe('acceptRisk', () => {
  it('adds an entry to exceptions.yaml, keeping the file\'s comment, and returns it', async () => {
    const dir = await projectWithScan();
    expect(await acceptRisk(dir, OK, NOW)).toEqual({ finding_id: 'hdr-hsts@portal', owner: 'dev-lead', reason: 'HSTS rolls out with the new proxy', expires: '2026-12-31' });
    expect(await loadExceptions(dir)).toHaveLength(1);
    const text = readFileSync(path.join(dir, '.secagent', 'knowledge', 'exceptions.yaml'), 'utf8');
    expect(text).toContain('# Accepted risks.');
    expect(text).not.toContain('exceptions: []');
    await acceptRisk(dir, { ...OK, findingId: 'code-leak@code', reason: 'rotating the key next sprint' }, NOW);
    expect((await loadExceptions(dir)).map((e) => e.finding_id)).toEqual(['hdr-hsts@portal', 'code-leak@code']);
  });

  it.each([
    'needs: a review # not a comment',
    'quotes " and \' and a colon: here, [brackets] {braces} - dash',
    'two lines\nsecond line, still the reason',
    'ünïcödé and emoji 🔐 in the reason',
    '- starts like a list item',
  ])('keeps awkward text in the owner and reason intact, so the file still loads: %j', async (reason) => {
    const dir = await projectWithScan();
    await acceptRisk(dir, { ...OK, owner: 'O\'Brien: "lead" # 1', reason }, NOW);
    const [entry] = await loadExceptions(dir);
    expect(entry).toMatchObject({ finding_id: 'hdr-hsts@portal', owner: 'O\'Brien: "lead" # 1', reason: reason.trim(), expires: '2026-12-31' });
  });

  it('creates the file when it is missing', async () => {
    const dir = await projectWithScan();
    await writeFiles(dir, { '.secagent/knowledge/exceptions.yaml': '' });
    await acceptRisk(dir, OK, NOW);
    expect(await loadExceptions(dir)).toHaveLength(1);
  });

  it('needs a scan, and a finding from it', async () => {
    const dir = await makeProject();
    await expect(acceptRisk(dir, OK, NOW)).rejects.toThrow('No scan yet: run secagent scan first');
    await new FindingsStore(dir).write(fixtureRecord());
    await expect(acceptRisk(dir, { ...OK, findingId: 'nope@x' }, NOW)).rejects.toThrow(/No finding "nope@x".*hdr-hsts@portal/s);
  });

  it('accepts only open findings: not unverifiable, fixed or already accepted ones', async () => {
    const dir = await projectWithScan();
    await expect(acceptRisk(dir, { ...OK, findingId: 'ssh-root@web-1' }, NOW)).rejects.toThrow(/unverifiable.*only open/);
    await expect(acceptRisk(dir, { ...OK, findingId: 'tls-ok@portal' }, NOW)).rejects.toThrow(/fixed.*only open/);
    const record = fixtureRecord();
    await new FindingsStore(dir).write({ ...record, findings: record.findings.map((f) => (f.id === 'hdr-hsts@portal' ? { ...f, status: 'accepted_risk' as const } : f)) });
    await acceptRisk(dir, OK, NOW).then(
      () => { throw new Error('should have failed'); },
      (e) => expect(e.message).toMatch(/accepted_risk.*only open/),
    );
  });

  it('refuses a second active exception for the same finding', async () => {
    const dir = await projectWithScan();
    await acceptRisk(dir, OK, NOW);
    await expect(acceptRisk(dir, { ...OK, until: '2027-01-15' }, NOW)).rejects.toThrow(/already accepted until 2026-12-31/);
  });

  it.each([
    [{ owner: '  ' }, /owner/],
    [{ reason: 'too short' }, /reason.*10/],
    [{ until: '31-12-2026' }, /YYYY-MM-DD/],
    [{ until: '2026-02-30' }, /not a real date/],
    [{ until: '2026-10-28' }, /after today/],
    [{ until: '2025-01-01' }, /after today/],
    [{ until: '2027-12-31' }, /one year/],
  ])('rejects bad input %j', async (patch, message) => {
    const dir = await projectWithScan();
    await expect(acceptRisk(dir, { ...OK, ...patch }, NOW)).rejects.toThrow(message);
    await expect(acceptRisk(dir, { ...OK, ...patch }, NOW)).rejects.toBeInstanceOf(KbError);
    expect(await loadExceptions(dir)).toEqual([]);
  });

  it('measures "today" with the clock it is given', async () => {
    const dir = await projectWithScan();
    await expect(acceptRisk(dir, { ...OK, until: '2026-10-29' }, FIXED_NOW)).resolves.toBeDefined();
  });
});
