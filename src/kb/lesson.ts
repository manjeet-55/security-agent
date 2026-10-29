import path from 'node:path';
import { parse, stringify } from 'yaml';
import { z } from 'zod';

const DATE = /^\d{4}-\d{2}-\d{2}$/;

export const LessonMetaSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/, 'use lowercase letters, digits and dashes'),
    title: z.string().min(1),
    /** Check types the lesson is about (empty: general). */
    applies_to: z.array(z.string().min(1)).default([]),
    tags: z.array(z.string().min(1)).default([]),
    source_url: z.url({ protocol: /^https$/ }).optional(),
    quote: z.string().min(1).optional(),
    retrieved_at: z.string().regex(DATE).optional(),
    added_by: z.string().regex(/^(seed|learn-\d{4}-\d{2}-\d{2})$/, 'added_by is "seed" or "learn-YYYY-MM-DD"'),
    review: z.enum(['approved', 'pending']),
    reviewed_by: z.string().min(1).optional(),
    reviewed_at: z.string().regex(DATE).optional(),
  })
  .superRefine((m, ctx) => {
    if (m.added_by !== 'seed') {
      for (const key of ['source_url', 'quote', 'retrieved_at'] as const) {
        if (m[key] === undefined) ctx.addIssue({ code: 'custom', path: [key], message: `learned lessons must carry ${key} (spec §8.4 provenance)` });
      }
    }
    if (m.review === 'approved') {
      for (const key of ['reviewed_by', 'reviewed_at'] as const) {
        if (m[key] === undefined) ctx.addIssue({ code: 'custom', path: [key], message: `approved lessons must record ${key}` });
      }
    }
  });

export type LessonMeta = z.infer<typeof LessonMetaSchema>;

export interface Lesson extends LessonMeta {
  body: string;
  file: string;
  layer: 'global' | 'project';
}

export class KbError extends Error {
  override name = 'KbError';
}

const FRONTMATTER = /^---\r?\n([\s\S]*?)\r?\n---\r?\n?([\s\S]*)$/;

export function parseLesson(text: string, file: string, layer: Lesson['layer']): Lesson {
  const m = FRONTMATTER.exec(text);
  if (!m) throw new KbError(`${file}: missing YAML frontmatter between --- lines`);
  let raw: unknown;
  try {
    raw = parse(m[1] ?? '');
  } catch (e) {
    throw new KbError(`${file}: invalid YAML frontmatter: ${e instanceof Error ? e.message : String(e)}`);
  }
  const parsed = LessonMetaSchema.safeParse(raw);
  if (!parsed.success) {
    throw new KbError(`${file}: ${parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ')}`);
  }
  const expected = path.basename(file, '.md');
  if (parsed.data.id !== expected) throw new KbError(`${file}: id "${parsed.data.id}" must match the file name "${expected}"`);
  return { ...parsed.data, body: (m[2] ?? '').trim(), file, layer };
}

export function serializeLesson(meta: LessonMeta, body: string): string {
  return `---\n${stringify(meta).trimEnd()}\n---\n${body.trim()}\n`;
}
