import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadCheckInstances } from '../../src/checks/catalog.js';
import { CHECK_TYPES } from '../../src/checks/registry.js';
import { KbError } from '../../src/kb/lesson.js';
import { kbRead, kbSearch, loadKnowledge, loadLessons, type Knowledge } from '../../src/kb/store.js';
import { GLOBAL_CHECKS_DIR, GLOBAL_LESSONS_DIR } from '../../src/paths.js';
import { makeProject } from '../helpers/project.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

async function knowledge(): Promise<Knowledge> {
  return { lessons: await loadLessons({ global: GLOBAL_LESSONS_DIR }), checks: await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES) };
}

const PENDING = `---
id: local-proxy-quirk
title: Our proxy rewrites the Host header
tags: [nginx, local]
added_by: learn-2026-10-29
source_url: https://nginx.org/en/docs/http/ngx_http_proxy_module.html
quote: the Host header field is passed
retrieved_at: 2026-10-29
review: pending
---
The staging proxy rewrites Host, so HSTS checks must use the public name.
`;

describe('knowledge base', () => {
  it('loads the seven approved seed lessons', async () => {
    const lessons = await loadLessons({ global: GLOBAL_LESSONS_DIR });
    expect(lessons.map((l) => l.id)).toEqual([
      'distro-backport-false-positive',
      'evidence-only-reports',
      'header-budget-proxy-buffer',
      'lb-bypass-direct-ip',
      'pkg-source-outside-auto-updates',
      'stale-dns-records',
      'unreachable-is-not-fixed',
    ]);
    expect(lessons.every((l) => l.review === 'approved' && l.added_by === 'seed')).toBe(true);
  });

  it('rejects a project lesson that reuses a global id', async () => {
    const project = await tempDir();
    await writeFiles(project, { 'stale-dns-records.md': '---\nid: stale-dns-records\ntitle: x\nadded_by: seed\nreview: pending\n---\nx' });
    await expect(loadLessons({ global: GLOBAL_LESSONS_DIR, project })).rejects.toThrow(/defined twice/);
  });

  it('a missing project lessons dir is empty, not an error', async () => {
    expect((await loadLessons({ global: GLOBAL_LESSONS_DIR, project: '/nonexistent/secagent' })).length).toBe(7);
  });

  it('a broken project lesson is an error that names its file', async () => {
    const dir = await makeProject();
    await writeFiles(dir, { '.secagent/knowledge/lessons/broken.md': 'no frontmatter' });
    await expect(loadKnowledge(dir, [])).rejects.toThrow(/broken\.md/);
    await expect(loadKnowledge(dir, [])).rejects.toBeInstanceOf(KbError);
  });

  it('ranks the backport lesson first for a banner CVE query', async () => {
    const hits = kbSearch(await knowledge(), 'openssh backport scanner');
    expect(hits[0]).toMatchObject({ id: 'distro-backport-false-positive', kind: 'lesson', review: 'approved' });
  });

  it('filters by tags (all must match)', async () => {
    const hits = kbSearch(await knowledge(), '', ['nginx', 'proxy_buffer_size']);
    expect(hits.map((h) => h.id)).toEqual(['header-budget-proxy-buffer']);
  });

  it('finds check instances too, by their plain-language why as well as their title', async () => {
    const k = await knowledge();
    expect(kbSearch(k, 'hsts').some((h) => h.id === 'hdr-hsts' && h.kind === 'check')).toBe(true);
    expect(kbSearch(k, 'clickjacking').some((h) => h.id === 'hdr-frame-options')).toBe(true);
  });

  it('a project lesson is searchable, and a pending one says it is pending', async () => {
    const dir = await makeProject();
    await writeFiles(dir, { '.secagent/knowledge/lessons/local-proxy-quirk.md': PENDING });
    const k = await loadKnowledge(dir, await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES));
    const hits = kbSearch(k, 'staging proxy host');
    expect(hits[0]).toMatchObject({ id: 'local-proxy-quirk', kind: 'lesson', review: 'pending' });
    expect(k.lessons).toHaveLength(8);
  });

  it('reads a lesson, a check, the index, notes and exceptions; unknown ids are errors', async () => {
    const k = await knowledge();
    const dir = await makeProject();
    expect(await kbRead(k, 'unreachable-is-not-fixed', dir)).toMatchObject({ id: 'unreachable-is-not-fixed', kind: 'lesson', review: 'approved' });
    expect(await kbRead(k, 'hdr-hsts', dir)).toMatchObject({ kind: 'check' });
    expect((await kbRead(k, 'INDEX', dir)).text).toContain('distro-backport-false-positive');
    expect((await kbRead(k, 'notes', dir)).text).toContain('Project security notes');
    expect((await kbRead(k, 'exceptions', dir)).text).toContain('exceptions: []');
    await expect(kbRead(k, 'nope', dir)).rejects.toThrow(/kb_search/);
  });

  it('never reads outside the knowledge folders, whatever the id', async () => {
    const k = await knowledge();
    const dir = await makeProject();
    for (const id of ['../../project', '../project.yaml', path.join('..', '..', 'etc', 'passwd'), 'notes/../../project.yaml']) {
      await expect(kbRead(k, id, dir)).rejects.toThrow(/No knowledge entry/);
    }
  });
});
