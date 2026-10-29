import { z } from 'zod';
import { createProjectReader, isGenericExempt, listGitFiles, listWalkedFiles, type FileListing } from '../../code/files.js';
import { GitError, repoState, type RepoState } from '../../code/git.js';
import { scanText } from '../../code/patterns.js';
import { mapLimit } from '../../util/pool.js';
import type { CheckOutput, CheckType } from '../check-type.js';
import { CODE_SUBJECT_ID, memoize, type CheckContext, type CheckSubject } from '../context.js';
import { ObservationError } from '../errors.js';

export const codeSecretsParams = z.discriminatedUnion('rule', [z.object({ rule: z.literal('working_tree') })]);
export type CodeSecretsParams = z.infer<typeof codeSecretsParams>;

type CodeSubject = Extract<CheckSubject, { kind: 'code' }>;

interface Hit {
  path: string;
  line: number;
  pattern: string;
  fingerprint: string;
}

const READ_CONCURRENCY = 8;
/** Findings named in the one-line summary; the evidence file lists them all. */
const SUMMARY_HITS = 10;
const SUMMARY_PATHS = 5;
/** Hits kept in the check result's details; the evidence file keeps up to EVIDENCE_HITS. */
const DETAIL_HITS = 50;
const EVIDENCE_HITS = 1000;

function getRepo(ctx: CheckContext, dir: string): Promise<RepoState> {
  return memoize(ctx, `CODE_REPO ${dir}`, () => repoState(dir));
}

/** git when the project is a repository, a directory walk when it is not; any other git trouble is unverifiable. */
function getListing(ctx: CheckContext, dir: string): Promise<{ listing: FileListing; note?: string }> {
  return memoize(ctx, `CODE_FILES ${dir}`, async () => {
    const repo = await getRepo(ctx, dir);
    switch (repo.state) {
      case 'repo':
        try {
          return { listing: await listGitFiles(dir, ctx.project.code) };
        } catch (e) {
          if (e instanceof GitError) throw new ObservationError('GIT_FAILED', `The project's file list could not be read: ${e.message}.`);
          throw e;
        }
      case 'none':
        return { listing: await listWalkedFiles(dir, ctx.project.code) };
      case 'git_missing':
        return {
          listing: await listWalkedFiles(dir, ctx.project.code),
          note: 'git was not found, so the directory was walked and .gitignore was not applied',
        };
      case 'error':
        throw new ObservationError('GIT_FAILED', `The project could not be examined with git: ${repo.reason}.`);
    }
  });
}

function summarise(items: readonly string[], limit = SUMMARY_PATHS): string {
  const shown = items.slice(0, limit).join(', ');
  return items.length > limit ? `${shown} and ${items.length - limit} more` : shown;
}

function describeHit(h: Hit): string {
  return `${h.path}:${h.line} ${h.pattern} [${h.fingerprint}]`;
}

async function workingTree(ctx: CheckContext, subject: CodeSubject): Promise<CheckOutput> {
  const cfg = ctx.project.code;
  const { listing, note } = await getListing(ctx, subject.dir);
  const reader = createProjectReader(subject.dir);

  const tooLarge: string[] = [];
  const unreadable: Array<{ path: string; code: string }> = [];
  let binary = 0;
  let absent = 0;
  let scanned = 0;
  const found = new Map<string, Hit>();

  await mapLimit(listing.files, READ_CONCURRENCY, async (rel) => {
    const read = await reader.read(rel, cfg.max_file_bytes);
    switch (read.kind) {
      case 'text':
        scanned += 1;
        for (const h of scanText(read.text, { generic: !isGenericExempt(rel) })) {
          found.set(`${rel}\0${h.line}\0${h.pattern}\0${h.fingerprint}`, { path: rel, line: h.line, pattern: h.pattern, fingerprint: h.fingerprint });
        }
        return;
      case 'too_large':
        tooLarge.push(rel);
        return;
      case 'unreadable':
        unreadable.push({ path: rel, code: read.code });
        return;
      case 'binary':
        binary += 1;
        return;
      case 'absent':
        absent += 1;
        return;
    }
  });

  const hits = [...found.values()].sort((a, b) => a.path.localeCompare(b.path) || a.line - b.line || a.pattern.localeCompare(b.pattern) || a.fingerprint.localeCompare(b.fingerprint));
  tooLarge.sort();
  unreadable.sort((a, b) => a.path.localeCompare(b.path));

  const gaps: string[] = [];
  if (tooLarge.length > 0) {
    gaps.push(`${tooLarge.length} file(s) larger than ${cfg.max_file_bytes} bytes (${summarise(tooLarge)}); raise code.max_file_bytes or list them in code.exclude`);
  }
  if (unreadable.length > 0) gaps.push(`${unreadable.length} file(s) could not be read (${summarise(unreadable.map((u) => `${u.path} ${u.code}`))})`);
  if (listing.unreadable_dirs.length > 0) gaps.push(`${listing.unreadable_dirs.length} director(ies) could not be read (${summarise(listing.unreadable_dirs)})`);
  if (listing.over_max_files > 0) {
    const bound = listing.mode === 'walk' ? 'at least ' : '';
    gaps.push(`${bound}${listing.over_max_files} file(s) beyond code.max_files (${cfg.max_files}) were not read; raise it or list generated directories in code.exclude`);
  }

  const evidence_id = await ctx.evidence.put('code', CODE_SUBJECT_ID, `secret scan of ${scanned} file(s) (${listing.mode})`, {
    mode: listing.mode,
    ...(note ? { note } : {}),
    files_listed: listing.files.length,
    files_scanned: scanned,
    binary_skipped: binary,
    not_regular_files: absent,
    hits: hits.slice(0, EVIDENCE_HITS),
    hit_count: hits.length,
    skipped: { too_large: tooLarge, unreadable, over_max_files: listing.over_max_files, unreadable_dirs: listing.unreadable_dirs },
    limits: { max_files: cfg.max_files, max_file_bytes: cfg.max_file_bytes },
  });

  const how = listing.mode === 'git' ? 'tracked and untracked files, .gitignore applied' : `directory walk with default excludes${note ? `; ${note}` : ''}`;
  if (hits.length > 0) {
    const files = new Set(hits.map((h) => h.path)).size;
    const shown = hits.slice(0, SUMMARY_HITS).map(describeHit).join('; ');
    const more = hits.length > SUMMARY_HITS ? `; and ${hits.length - SUMMARY_HITS} more` : '';
    const partial = gaps.length > 0 ? ` Not everything was scanned: ${gaps.join('; ')}.` : '';
    return {
      outcome: 'fail',
      observed: `${hits.length} potential secret(s) in ${files} file(s): ${shown}${more}. Values are not shown; rotate them.${partial}`,
      evidence_id,
      details: { mode: listing.mode, files_scanned: scanned, hit_count: hits.length, hits: hits.slice(0, DETAIL_HITS) },
    };
  }
  if (gaps.length > 0) {
    return {
      outcome: 'unverifiable',
      observed: `Scanned ${scanned} file(s) and found nothing, but not everything was scanned: ${gaps.join('; ')}. This does not mean the issue is fixed.`,
      evidence_id,
    };
  }
  return { outcome: 'pass', observed: `no secrets found in ${scanned} file(s) (${how})`, evidence_id };
}

export const codeSecretsCheck: CheckType<CodeSecretsParams> = {
  type: 'code_secrets',
  supports: ['code'],
  params: codeSecretsParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'code') throw new Error('code_secrets runs on the project directory only');
    switch (p.rule) {
      case 'working_tree':
        return workingTree(ctx, subject);
    }
  },
};
