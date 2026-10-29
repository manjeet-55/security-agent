import { mkdir, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { GLOBAL_LESSONS_DIR } from '../paths.js';
import { KbError, parseLesson, serializeLesson, type Lesson, type LessonMeta } from './lesson.js';
import { loadSourceHosts, normaliseQuote, readFetched, sourceProblem } from './sources.js';
import { loadLessons, projectLessonsDir } from './store.js';

export interface LessonDraft {
  id: string;
  title: string;
  body: string;
  tags?: string[];
  applies_to?: string[];
  source_url: string;
  quote: string;
}

const MAX_PENDING = 50;

/**
 * Saves a lesson an AI assistant proposes, as pending, in the project's knowledge. It must cite an allowlisted page fetched with
 * fetch_source, and the quote must appear in that page word for word (whitespace and curly quotes aside). Pending lessons can add
 * findings or raise severity but never back calling something safe; a person approves them with secagent kb review.
 */
export async function writeLesson(projectDir: string, d: LessonDraft, now: Date): Promise<Lesson> {
  const problem = sourceProblem(d.source_url, await loadSourceHosts());
  if (problem) throw new KbError(problem);
  const fetched = await readFetched(projectDir, d.source_url);
  if (!fetched) throw new KbError(`Fetch ${d.source_url} with fetch_source first; a lesson can only quote a page secagent has read.`);
  const quote = normaliseQuote(d.quote);
  if (quote.length < 20) throw new KbError('The quote must be at least 20 characters, copied from the page.');
  if (!normaliseQuote(fetched.text).includes(quote)) throw new KbError('The quote does not appear in the fetched page. Copy a sentence from it exactly.');

  const existing = await loadLessons({ global: GLOBAL_LESSONS_DIR, project: projectLessonsDir(projectDir) });
  if (existing.some((l) => l.id === d.id)) throw new KbError(`A lesson "${d.id}" already exists; pick another id.`);
  if (existing.filter((l) => l.review === 'pending').length >= MAX_PENDING) throw new KbError(`There are already ${MAX_PENDING} pending lessons; ask a person to review them (secagent kb review).`);

  const day = now.toISOString().slice(0, 10);
  const meta: LessonMeta = {
    id: d.id,
    title: d.title,
    applies_to: d.applies_to ?? [],
    tags: d.tags ?? [],
    source_url: d.source_url,
    quote,
    retrieved_at: fetched.fetched_at.slice(0, 10),
    added_by: `learn-${day}`,
    review: 'pending',
  };
  const file = path.join(projectLessonsDir(projectDir), `${d.id}.md`);
  const text = serializeLesson(meta, d.body);
  const lesson = parseLesson(text, file, 'project');
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, text, 'utf8');
  return lesson;
}

export async function pendingLessons(projectDir: string): Promise<Lesson[]> {
  return (await loadLessons({ global: GLOBAL_LESSONS_DIR, project: projectLessonsDir(projectDir) })).filter((l) => l.review === 'pending');
}

async function projectLesson(projectDir: string, id: string): Promise<{ file: string; lesson: Lesson }> {
  if (!/^[a-z0-9][a-z0-9-]*$/.test(id)) throw new KbError(`"${id}" is not a lesson id`);
  const file = path.join(projectLessonsDir(projectDir), `${id}.md`);
  const names = await readdir(projectLessonsDir(projectDir)).catch(() => [] as string[]);
  if (!names.includes(`${id}.md`)) throw new KbError(`No project lesson "${id}". Run secagent kb review to list pending ones.`);
  return { file, lesson: parseLesson(await readFile(file, 'utf8'), file, 'project') };
}

/** A person approves a pending project lesson: it can then back lowering a risk. */
export async function approveLesson(projectDir: string, id: string, by: string, now: Date): Promise<Lesson> {
  if (by.trim() === '') throw new KbError('--by must name the person approving the lesson');
  const { file, lesson } = await projectLesson(projectDir, id);
  if (lesson.review === 'approved') throw new KbError(`"${id}" is already approved`);
  const { body, file: _f, layer: _l, ...meta } = lesson;
  const text = serializeLesson({ ...meta, review: 'approved', reviewed_by: by.trim(), reviewed_at: now.toISOString().slice(0, 10) }, body);
  parseLesson(text, file, 'project');
  await writeFile(file, text, 'utf8');
  return parseLesson(text, file, 'project');
}

/** A person rejects a pending project lesson: the file is removed. */
export async function rejectLesson(projectDir: string, id: string): Promise<void> {
  const { file, lesson } = await projectLesson(projectDir, id);
  if (lesson.review !== 'pending') throw new KbError(`"${id}" is approved; edit or delete the file to change it`);
  await rm(file);
}
