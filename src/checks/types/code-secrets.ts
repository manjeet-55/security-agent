import { z } from 'zod';
import { classifySensitiveFile, KIND_LABEL, npmrcHoldsAuthToken, type SensitiveKind } from '../../code/envfiles.js';
import { compileExcludes } from '../../code/exclude.js';
import { createProjectReader, isGenericExempt, isScannablePath, listGitFiles, listWalkedFiles, type FileListing } from '../../code/files.js';
import { gitListFiles, GitError, GitMissingError, repoState, type RepoState } from '../../code/git.js';
import { scanHistory, type HistoryScan } from '../../code/history.js';
import { scanText } from '../../code/patterns.js';
import { mapLimit } from '../../util/pool.js';
import type { CheckOutput, CheckType } from '../check-type.js';
import { CODE_SUBJECT_ID, memoize, type CheckContext, type CheckSubject } from '../context.js';
import { ObservationError } from '../errors.js';

const positive = z.number().int().min(1);

export const codeSecretsParams = z.discriminatedUnion('rule', [
  z.object({ rule: z.literal('working_tree') }).strict(),
  /** Sensitive files (.env, keys, state) that git tracks. */
  z.object({ rule: z.literal('env_tracked') }).strict(),
  /** Sensitive files that exist, are not tracked and are not ignored: one `git add .` from being committed. */
  z.object({ rule: z.literal('env_not_ignored') }).strict(),
  /** Secrets in lines that any commit on any ref ever added. */
  z
    .object({
      rule: z.literal('history'),
      max_commits: positive.default(2000),
      max_diff_bytes: positive.default(20_000_000),
      timeout_ms: positive.default(60_000),
    })
    .strict(),
]);
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

/** Resolves when `dir` is a git work tree; otherwise the check cannot be answered, and that is unverifiable, never a pass. */
async function requireRepo(ctx: CheckContext, dir: string, what: string): Promise<void> {
  const repo = await getRepo(ctx, dir);
  switch (repo.state) {
    case 'repo':
      return;
    case 'none':
      throw new ObservationError('NOT_A_REPOSITORY', `The project directory is not a git repository, so ${what} cannot be checked.`);
    case 'git_missing':
      throw new ObservationError('GIT_MISSING', `git was not found on PATH, so ${what} cannot be checked.`);
    case 'error':
      throw new ObservationError('GIT_FAILED', `The project could not be examined with git (${repo.reason}), so ${what} cannot be checked.`);
  }
}

interface SensitiveFile {
  path: string;
  kind: SensitiveKind;
}

/** Sensitive files among the paths git lists for `selection`, after code.exclude. Content is read only to judge an .npmrc. */
async function findSensitiveFiles(
  ctx: CheckContext,
  dir: string,
  selection: 'tracked' | 'untracked',
): Promise<{ examined: number; files: SensitiveFile[]; gaps: string[] }> {
  const cfg = ctx.project.code;
  const excluded = compileExcludes(cfg.exclude);
  let listed: string[];
  try {
    listed = await gitListFiles(dir, selection);
  } catch (e) {
    if (e instanceof GitError) throw new ObservationError('GIT_FAILED', `The project's file list could not be read: ${e.message}.`);
    if (e instanceof GitMissingError) throw new ObservationError('GIT_MISSING', 'git was not found on PATH.');
    throw e;
  }
  const paths = listed.filter((rel) => isScannablePath(rel) && !excluded(rel, false));
  const reader = createProjectReader(dir);
  const files: SensitiveFile[] = [];
  const tooLarge: string[] = [];
  const unreadable: string[] = [];
  for (const rel of paths) {
    const kind = classifySensitiveFile(rel);
    if (kind === undefined) continue;
    if (kind !== 'npmrc') {
      files.push({ path: rel, kind });
      continue;
    }
    const read = await reader.read(rel, cfg.max_file_bytes);
    if (read.kind === 'text') {
      if (npmrcHoldsAuthToken(read.text)) files.push({ path: rel, kind });
    } else if (read.kind === 'too_large') {
      tooLarge.push(rel);
    } else if (read.kind === 'unreadable') {
      unreadable.push(`${rel} ${read.code}`);
    }
  }
  const gaps: string[] = [];
  if (tooLarge.length > 0) gaps.push(`${tooLarge.length} .npmrc file(s) larger than ${cfg.max_file_bytes} bytes could not be checked for a token (${summarise(tooLarge)})`);
  if (unreadable.length > 0) gaps.push(`${unreadable.length} .npmrc file(s) could not be read (${summarise(unreadable)})`);
  return { examined: paths.length, files, gaps };
}

function describeFile(f: SensitiveFile): string {
  return `${f.path} (${KIND_LABEL[f.kind]})`;
}

async function sensitiveFileRule(ctx: CheckContext, subject: CodeSubject, rule: 'env_tracked' | 'env_not_ignored'): Promise<CheckOutput> {
  const tracked = rule === 'env_tracked';
  await requireRepo(ctx, subject.dir, tracked ? 'which sensitive files are tracked' : 'which sensitive files are unprotected');
  const { examined, files, gaps } = await findSensitiveFiles(ctx, subject.dir, tracked ? 'tracked' : 'untracked');
  const what = tracked ? 'tracked' : 'untracked and not ignored';
  const evidence_id = await ctx.evidence.put('code', CODE_SUBJECT_ID, `${what} sensitive files: ${files.length} of ${examined} file(s) examined`, {
    rule,
    files_examined: examined,
    files,
    gaps,
  });
  const partial = gaps.length > 0 ? ` Not everything was checked: ${gaps.join('; ')}.` : '';
  if (files.length > 0) {
    const shown = files.slice(0, SUMMARY_HITS).map(describeFile).join(', ');
    const more = files.length > SUMMARY_HITS ? `, and ${files.length - SUMMARY_HITS} more` : '';
    const observed = tracked
      ? `${files.length} sensitive file(s) are tracked by git: ${shown}${more}. Whatever they hold is in the repository history for everyone with a copy: rotate it, run "git rm --cached" on them and add them to .gitignore.`
      : `${files.length} sensitive file(s) exist but are neither tracked nor ignored, so one "git add ." would commit them: ${shown}${more}. Add them to .gitignore.`;
    return { outcome: 'fail', observed: observed + partial, evidence_id, details: { files_examined: examined, files: files.slice(0, DETAIL_HITS) } };
  }
  if (gaps.length > 0) {
    return { outcome: 'unverifiable', observed: `Found no sensitive files, but not everything was checked: ${gaps.join('; ')}. This does not mean the issue is fixed.`, evidence_id };
  }
  return {
    outcome: 'pass',
    observed: tracked
      ? `none of the ${examined} tracked file(s) is an environment, key, credentials or state file`
      : `no untracked file outside .gitignore is an environment, key, credentials or state file (${examined} examined)`,
    evidence_id,
  };
}

const SHORT_SHA = 8;

interface HistoryFinding {
  path: string;
  line: number;
  pattern: string;
  fingerprint: string;
  /** The oldest commit that added it. */
  commit: string;
  /** How many commits added it. */
  commits: number;
}

function groupHistoryHits(scan: HistoryScan, excluded: (rel: string, isDir: boolean) => boolean): HistoryFinding[] {
  const grouped = new Map<string, HistoryFinding>();
  // git log runs newest first: the last commit seen for a secret is the one that introduced it.
  for (const h of scan.hits) {
    if (!isScannablePath(h.path) || excluded(h.path, false)) continue;
    const key = `${h.path}\0${h.pattern}\0${h.fingerprint}`;
    const have = grouped.get(key);
    grouped.set(key, { path: h.path, line: h.line, pattern: h.pattern, fingerprint: h.fingerprint, commit: h.sha, commits: (have?.commits ?? 0) + 1 });
  }
  return [...grouped.values()].sort((a, b) => a.path.localeCompare(b.path) || a.pattern.localeCompare(b.pattern) || a.fingerprint.localeCompare(b.fingerprint));
}

async function historyRule(ctx: CheckContext, subject: CodeSubject, p: Extract<CodeSecretsParams, { rule: 'history' }>): Promise<CheckOutput> {
  const cfg = ctx.project.code;
  if (!cfg.history) {
    throw new ObservationError('HISTORY_DISABLED', 'The git history scan is turned off (code.history is false in project.yaml), so history was not checked.');
  }
  await requireRepo(ctx, subject.dir, 'git history');
  let scan: HistoryScan;
  try {
    scan = await scanHistory(subject.dir, { maxCommits: p.max_commits, maxDiffBytes: p.max_diff_bytes, timeoutMs: p.timeout_ms });
  } catch (e) {
    if (e instanceof GitError) throw new ObservationError('GIT_FAILED', `The git history could not be read: ${e.message}.`);
    if (e instanceof GitMissingError) throw new ObservationError('GIT_MISSING', 'git was not found on PATH, so git history cannot be checked.');
    throw e;
  }

  const found = groupHistoryHits(scan, compileExcludes(cfg.exclude));
  const gaps: string[] = [];
  if (scan.stopped === 'commits') gaps.push(`only the newest ${scan.commits} commit(s) were read (limit ${p.max_commits}), older ones were not`);
  if (scan.stopped === 'bytes') gaps.push(`reading stopped at the limit of ${p.max_diff_bytes} bytes of diffs, so older commits were not read`);
  if (scan.stopped === 'timeout') gaps.push(`the time limit (${p.timeout_ms} ms) ran out before the whole history was read`);
  if (scan.shallow) gaps.push('this is a shallow clone, so older commits are missing (git fetch --unshallow gets them)');
  if (scan.partial) gaps.push('this is a partial clone, and objects it does not have locally are not fetched by this scan');

  const evidence_id = await ctx.evidence.put('code', CODE_SUBJECT_ID, `secret scan of git history: ${scan.commits} commit(s), ${found.length} finding(s)`, {
    commits_scanned: scan.commits,
    diff_bytes: scan.diffBytes,
    ...(scan.stopped ? { stopped: scan.stopped } : {}),
    shallow: scan.shallow,
    partial: scan.partial,
    hit_count: found.length,
    hits: found.slice(0, EVIDENCE_HITS),
    gaps,
    limits: { max_commits: p.max_commits, max_diff_bytes: p.max_diff_bytes, timeout_ms: p.timeout_ms },
  });

  const partial = gaps.length > 0 ? ` Not all history was read: ${gaps.join('; ')}.` : '';
  if (found.length > 0) {
    const shown = found
      .slice(0, SUMMARY_HITS)
      .map((h) => `${h.path} ${h.pattern} [${h.fingerprint}] added in ${h.commit.slice(0, SHORT_SHA)}`)
      .join('; ');
    const more = found.length > SUMMARY_HITS ? `; and ${found.length - SUMMARY_HITS} more` : '';
    return {
      outcome: 'fail',
      observed: `${found.length} secret(s) found in git history: ${shown}${more}. Values are not shown. Treat each as exposed and rotate it: removing a secret from the tree does not remove it from history.${partial}`,
      evidence_id,
      details: { commits_scanned: scan.commits, hit_count: found.length, hits: found.slice(0, DETAIL_HITS) },
    };
  }
  if (gaps.length > 0) {
    return { outcome: 'unverifiable', observed: `Read ${scan.commits} commit(s) and found nothing, but not all history was read: ${gaps.join('; ')}. This does not mean the issue is fixed.`, evidence_id };
  }
  return { outcome: 'pass', observed: `no secrets in the lines added by ${scan.commits} commit(s) on any branch or tag`, evidence_id };
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
      case 'env_tracked':
      case 'env_not_ignored':
        return sensitiveFileRule(ctx, subject, p.rule);
      case 'history':
        return historyRule(ctx, subject, p);
    }
  },
};
