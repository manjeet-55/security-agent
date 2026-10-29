import { copyFile, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { projectStateDir } from '../paths.js';
import { renderHtml } from './html.js';
import { renderMarkdown } from './markdown.js';
import { renderPdf } from './pdf.js';
import { buildReport, type ReportInput } from './model.js';

export type ReportFormat = 'md' | 'pdf' | 'html';

/**
 * Writes the report for a scan to .secagent/reports/<YYYYMMDD-HHMMSS>/report.<ext> (named after the scan time, so re-rendering a
 * scan overwrites its own report) and copies each file to .secagent/reports/latest.<ext>. Returns absolute paths.
 */
export async function writeReport(projectDir: string, input: ReportInput, opts: { formats: readonly ReportFormat[] }): Promise<{ files: string[]; latest: string[] }> {
  const reports = path.join(projectStateDir(projectDir), 'reports');
  const iso = input.record.scanned_at;
  const stamp = `${iso.slice(0, 10).replace(/-/g, '')}-${iso.slice(11, 19).replace(/:/g, '')}`;
  const dir = path.join(reports, stamp);
  await mkdir(dir, { recursive: true });
  const blocks = buildReport(input);
  const files: string[] = [];
  const latest: string[] = [];
  for (const format of opts.formats) {
    const file = path.join(dir, `report.${format}`);
    if (format === 'md') {
      await writeFile(file, renderMarkdown(blocks), 'utf8');
    } else if (format === 'html') {
      await writeFile(file, renderHtml(blocks, { title: `Security report: ${input.project.name}` }), 'utf8');
    } else {
      const title = `Security report: ${input.project.name}`;
      await writeFile(file, await renderPdf(blocks, { title, footer: `secagent · ${input.project.name}`, createdAt: new Date(iso) }));
    }
    const copy = path.join(reports, `latest.${format}`);
    await copyFile(file, copy);
    files.push(file);
    latest.push(copy);
  }
  return { files, latest };
}
