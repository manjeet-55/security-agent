import { readFile } from 'node:fs/promises';
import { parse } from 'yaml';
import { z } from 'zod';
import { FindingsStore } from './findings/store.js';
import { FINDING_STATUSES } from './types.js';

/** "pass" means the latest scan has no finding with that id (the check passed and was never open, or nothing applied). */
const Expected = z.enum([...FINDING_STATUSES, 'pass']);
const FileSchema = z.object({ findings: z.record(z.string().min(1), z.union([Expected, z.array(Expected).min(1)])) });

export interface EvalRow {
  id: string;
  expected: string[];
  actual: string;
  ok: boolean;
}

export class EvalError extends Error {
  override name = 'EvalError';
}

/** Compares the latest scan with an expected-results file: `findings: { <finding-id>: <status or [statuses]> }`. */
export async function evaluate(projectDir: string, expectedFile: string): Promise<EvalRow[]> {
  let raw: unknown;
  try {
    raw = parse(await readFile(expectedFile, 'utf8'));
  } catch (e) {
    throw new EvalError(`${expectedFile}: ${e instanceof Error ? e.message : String(e)}`);
  }
  const parsed = FileSchema.safeParse(raw);
  if (!parsed.success) throw new EvalError(`${expectedFile}: ${parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ')}`);
  const record = await new FindingsStore(projectDir).latest();
  if (!record) throw new EvalError('No scan yet: run secagent scan first');
  const actual = new Map(record.findings.map((f) => [f.id, f.status as string]));
  return Object.entries(parsed.data.findings).map(([id, exp]) => {
    const expected = Array.isArray(exp) ? exp : [exp];
    const got = actual.get(id) ?? 'pass';
    return { id, expected, actual: got, ok: expected.includes(got as never) };
  });
}
