import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import { projectStateDir } from '../paths.js';

/** A summary an AI assistant wrote for the report of one scan (through the MCP server). secagent does not verify it. */
export const SummarySchema = z.object({
  scanned_at: z.string(),
  summary: z.string(),
  proposals: z.array(z.string()).default([]),
  written_at: z.string(),
});
export type ReportSummary = z.infer<typeof SummarySchema>;

function summaryFile(projectDir: string): string {
  return path.join(projectStateDir(projectDir), 'reports', 'summary.json');
}

export async function writeSummary(projectDir: string, s: ReportSummary): Promise<void> {
  await mkdir(path.dirname(summaryFile(projectDir)), { recursive: true });
  await writeFile(summaryFile(projectDir), `${JSON.stringify(s, null, 2)}\n`, 'utf8');
}

/** The summary written for this scan, or undefined (none, unreadable, or written for another scan). */
export async function readSummary(projectDir: string, scannedAt: string): Promise<ReportSummary | undefined> {
  try {
    const parsed = SummarySchema.safeParse(JSON.parse(await readFile(summaryFile(projectDir), 'utf8')));
    return parsed.success && parsed.data.scanned_at === scannedAt ? parsed.data : undefined;
  } catch {
    return undefined;
  }
}
