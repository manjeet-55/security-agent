import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';
import { SEVERITIES, SUBJECT_KINDS } from '../types.js';
import type { AnyCheckType } from './check-type.js';

export const CheckInstanceSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
    type: z.string().min(1),
    title: z.string().min(1),
    severity: z.enum(SEVERITIES),
    applies_to: z.array(z.enum(SUBJECT_KINDS)).min(1),
    params: z.record(z.string(), z.unknown()).default({}),
    fix_hints: z.record(z.string(), z.string()).default({}),
    side_effects: z.array(z.string()).default([]),
    source_url: z.url({ protocol: /^https$/ }),
    quote: z.string().optional(),
    added_by: z.string().default('seed'),
    review: z.enum(['approved', 'pending']),
    reviewed_by: z.string().optional(),
    reviewed_at: z.string().optional(),
  })
  .refine((c) => c.added_by === 'seed' || c.quote !== undefined, {
    message: 'learned check instances must carry a verbatim quote from their source',
    path: ['quote'],
  });

export type CheckInstance = z.infer<typeof CheckInstanceSchema>;

export class CatalogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CatalogError';
  }
}

/** Loads every *.yaml instance in dir, validating it and its params against the registered type. */
export async function loadCheckInstances(dir: string, knownTypes: ReadonlyMap<string, AnyCheckType>): Promise<CheckInstance[]> {
  const files = (await readdir(dir)).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml')).sort();
  const instances: CheckInstance[] = [];
  const errors: string[] = [];
  const ids = new Set<string>();

  for (const file of files) {
    let raw: unknown;
    try {
      raw = parse(await readFile(path.join(dir, file), 'utf8'));
    } catch (e) {
      errors.push(`${file}: invalid YAML: ${(e as Error).message}`);
      continue;
    }
    const parsed = CheckInstanceSchema.safeParse(raw);
    if (!parsed.success) {
      errors.push(...parsed.error.issues.map((i) => `${file}: ${i.path.join('.') || '(root)'}: ${i.message}`));
      continue;
    }
    const type = knownTypes.get(parsed.data.type);
    if (!type) {
      errors.push(`${file}: unknown check type "${parsed.data.type}"`);
      continue;
    }
    const params = type.params.safeParse(parsed.data.params);
    if (!params.success) {
      errors.push(...params.error.issues.map((i) => `${file}: params.${i.path.join('.')}: ${i.message}`));
      continue;
    }
    if (ids.has(parsed.data.id)) {
      errors.push(`${file}: duplicate check id "${parsed.data.id}"`);
      continue;
    }
    ids.add(parsed.data.id);
    instances.push({ ...parsed.data, params: params.data as Record<string, unknown> });
  }

  if (errors.length > 0) {
    throw new CatalogError(`Invalid check catalog in ${dir}:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
  }
  return instances;
}
