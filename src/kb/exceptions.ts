import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';
import { projectKnowledgeDir } from '../paths.js';
import { KbError } from './lesson.js';

export const ExceptionSchema = z.object({
  finding_id: z.string().min(1),
  owner: z.string().min(1),
  reason: z.string().min(1),
  /** Last day the exception holds (inclusive), YYYY-MM-DD. */
  expires: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'expires must be a YYYY-MM-DD date'),
});
export type RiskException = z.infer<typeof ExceptionSchema>;

const FileSchema = z.object({ exceptions: z.array(ExceptionSchema).nullish() });

export async function loadExceptions(projectDir: string): Promise<RiskException[]> {
  const file = path.join(projectKnowledgeDir(projectDir), 'exceptions.yaml');
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw e;
  }
  let raw: unknown;
  try {
    raw = parse(text) ?? {};
  } catch (e) {
    throw new KbError(`${file}: invalid YAML: ${e instanceof Error ? e.message : String(e)}`);
  }
  const parsed = FileSchema.safeParse(raw);
  if (!parsed.success) throw new KbError(`${file}: ${parsed.error.issues.map((i) => `${i.path.join('.')}: ${i.message}`).join('; ')}`);
  return parsed.data.exceptions ?? [];
}

/** The entry covering this finding today, if any. An exception holds through its expires date. */
export function activeException(list: readonly RiskException[], findingId: string, now: Date): RiskException | undefined {
  const today = now.toISOString().slice(0, 10);
  return list.find((x) => x.finding_id === findingId && today <= x.expires);
}
