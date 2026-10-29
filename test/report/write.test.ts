import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { FindingsStore } from '../../src/findings/store.js';
import { initProject } from '../../src/project/init.js';
import { loadReportInput } from '../../src/report/model.js';
import { writeReport } from '../../src/report/write.js';
import { tempDir } from '../helpers/tmp.js';
import { fixtureRecord } from './fixture.js';

describe('writeReport', () => {
  it('has nothing to load before the first scan', async () => {
    const dir = await tempDir();
    await initProject(dir, {});
    expect(await loadReportInput(dir)).toBeUndefined();
  });

  it('writes a timestamped report and a latest copy under .secagent/reports', async () => {
    const dir = await tempDir();
    await initProject(dir, { name: 'shop' });
    await new FindingsStore(dir).write(fixtureRecord());
    const input = await loadReportInput(dir);
    expect(input).toBeDefined();
    const out = await writeReport(dir, input!, { formats: ['md'] });
    const reports = path.join(dir, '.secagent', 'reports');
    expect(out.files).toEqual([path.join(reports, '20261028-100000', 'report.md')]);
    expect(out.latest).toEqual([path.join(reports, 'latest.md')]);
    expect(readFileSync(out.latest[0]!, 'utf8')).toBe(readFileSync(out.files[0]!, 'utf8'));
    expect(readFileSync(out.latest[0]!, 'utf8')).toContain('# Security report: shop');
  });

  it('writes the PDF next to the Markdown, with a latest copy', async () => {
    const dir = await tempDir();
    await initProject(dir, { name: 'shop' });
    await new FindingsStore(dir).write(fixtureRecord());
    const out = await writeReport(dir, (await loadReportInput(dir))!, { formats: ['md', 'pdf'] });
    const reports = path.join(dir, '.secagent', 'reports');
    expect(out.latest).toEqual([path.join(reports, 'latest.md'), path.join(reports, 'latest.pdf')]);
    expect(readFileSync(path.join(reports, '20261028-100000', 'report.pdf')).subarray(0, 5).toString('latin1')).toBe('%PDF-');
    expect(readFileSync(out.latest[1]!).subarray(0, 5).toString('latin1')).toBe('%PDF-');
  });
});
