import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { stringify } from 'yaml';
import type { CheckInstance } from '../checks/catalog.js';
import { GLOBAL_LESSONS_DIR, projectKnowledgeDir } from '../paths.js';
import { renderIndex } from './index-md.js';
import { KbError, parseLesson, type Lesson } from './lesson.js';

export interface Knowledge {
  lessons: Lesson[];
  checks: CheckInstance[];
}

async function lessonsIn(dir: string, layer: Lesson['layer']): Promise<Lesson[]> {
  let names: string[];
  try {
    names = (await readdir(dir)).filter((n) => n.endsWith('.md')).sort();
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return [];
    throw e;
  }
  const out: Lesson[] = [];
  for (const name of names) {
    const file = path.join(dir, name);
    out.push(parseLesson(await readFile(file, 'utf8'), file, layer));
  }
  return out;
}

/** Global lessons plus the project's own; an id defined in both layers is an error. Sorted by id. */
export async function loadLessons(dirs: { global: string; project?: string }): Promise<Lesson[]> {
  const all = [...(await lessonsIn(dirs.global, 'global')), ...(dirs.project ? await lessonsIn(dirs.project, 'project') : [])];
  const seen = new Map<string, string>();
  for (const l of all) {
    const prev = seen.get(l.id);
    if (prev) throw new KbError(`lesson id "${l.id}" is defined twice: ${prev} and ${l.file}`);
    seen.set(l.id, l.file);
  }
  return all.sort((a, b) => a.id.localeCompare(b.id));
}

export function projectLessonsDir(projectDir: string): string {
  return path.join(projectKnowledgeDir(projectDir), 'lessons');
}

export async function loadKnowledge(projectDir: string, checks: CheckInstance[]): Promise<Knowledge> {
  return { lessons: await loadLessons({ global: GLOBAL_LESSONS_DIR, project: projectLessonsDir(projectDir) }), checks };
}

export interface KbHit {
  id: string;
  kind: 'lesson' | 'check';
  title: string;
  review: 'approved' | 'pending';
  tags: string[];
  score: number;
  snippet: string;
}

const MAX_HITS = 20;

function terms(query: string): string[] {
  return [...new Set(query.toLowerCase().split(/[^a-z0-9_.-]+/).filter((t) => t.length >= 2))];
}

function snippet(body: string, ts: readonly string[]): string {
  const line = body.split('\n').find((l) => ts.some((t) => l.toLowerCase().includes(t))) ?? body.split('\n')[0] ?? '';
  return line.length > 200 ? `${line.slice(0, 197)}...` : line;
}

/** Keyword search over ids, tags, titles and bodies (lessons) and ids, types, titles, why and fix hints (checks). */
export function kbSearch(k: Knowledge, query: string, tags: readonly string[] = []): KbHit[] {
  const ts = terms(query);
  const wanted = tags.map((t) => t.toLowerCase());
  const hits: KbHit[] = [];
  const score = (fields: Array<[string, number]>): number =>
    ts.reduce((sum, t) => sum + fields.reduce((s, [text, w]) => (text.toLowerCase().includes(t) ? s + w : s), 0), 0);

  for (const l of k.lessons) {
    if (!wanted.every((t) => l.tags.map((x) => x.toLowerCase()).includes(t))) continue;
    const s = ts.length === 0 ? 1 : score([[l.id, 3], [l.tags.join(' '), 3], [l.title, 2], [l.body, 1]]);
    if (s > 0) hits.push({ id: l.id, kind: 'lesson', title: l.title, review: l.review, tags: l.tags, score: s, snippet: snippet(l.body, ts) });
  }
  for (const c of k.checks) {
    const ctags = [c.type, ...c.applies_to];
    if (!wanted.every((t) => ctags.includes(t))) continue;
    const s = ts.length === 0 ? 1 : score([[c.id, 3], [c.type, 3], [c.title, 2], [c.why ?? '', 1], [Object.values(c.fix_hints).join(' '), 1]]);
    if (s > 0) hits.push({ id: c.id, kind: 'check', title: c.title, review: c.review, tags: ctags, score: s, snippet: c.why ?? c.title });
  }
  return hits.sort((a, b) => b.score - a.score || a.id.localeCompare(b.id)).slice(0, MAX_HITS);
}

export interface KbEntry {
  id: string;
  kind: 'lesson' | 'check' | 'index' | 'notes' | 'exceptions';
  review?: 'approved' | 'pending';
  text: string;
}

async function readOrEmpty(file: string): Promise<string> {
  try {
    return await readFile(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return '';
    throw e;
  }
}

/**
 * One entry by id. Special ids: INDEX (generated overview), notes (project notes.md), exceptions (exceptions.yaml). Any other id is
 * looked up among the loaded lessons and checks only, so an id can never name a file.
 */
export async function kbRead(k: Knowledge, id: string, projectDir: string): Promise<KbEntry> {
  if (id === 'INDEX') return { id, kind: 'index', text: renderIndex(k.lessons, k.checks) };
  if (id === 'notes') return { id, kind: 'notes', text: await readOrEmpty(path.join(projectKnowledgeDir(projectDir), 'notes.md')) };
  if (id === 'exceptions') return { id, kind: 'exceptions', text: await readOrEmpty(path.join(projectKnowledgeDir(projectDir), 'exceptions.yaml')) };
  const lesson = k.lessons.find((l) => l.id === id);
  if (lesson) {
    const { body, file: _file, layer: _layer, ...meta } = lesson;
    return { id, kind: 'lesson', review: lesson.review, text: `${stringify(meta).trimEnd()}\n\n${body}` };
  }
  const check = k.checks.find((c) => c.id === id);
  if (check) return { id, kind: 'check', review: check.review, text: stringify(check) };
  throw new KbError(`No knowledge entry "${id}". Use kb_search to find ids, or kb_read("INDEX") for the overview.`);
}
