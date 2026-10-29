import { describe, expect, it } from 'vitest';
import { KbError, parseLesson, serializeLesson } from '../../src/kb/lesson.js';

const META = `id: sample-lesson
title: A sample
applies_to: [http_header]
tags: [nginx]
added_by: seed
review: approved
reviewed_by: someone
reviewed_at: "2026-10-29"`;

describe('parseLesson', () => {
  it('parses frontmatter and body', () => {
    const l = parseLesson(`---\n${META}\n---\nBody text.\n`, '/k/sample-lesson.md', 'global');
    expect(l).toMatchObject({ id: 'sample-lesson', title: 'A sample', tags: ['nginx'], review: 'approved', body: 'Body text.', layer: 'global' });
  });

  it('rejects a file without frontmatter', () => {
    expect(() => parseLesson('no frontmatter', '/k/x.md', 'global')).toThrow(KbError);
  });

  it('requires provenance on learned lessons', () => {
    const learned = META.replace('added_by: seed', 'added_by: learn-2026-10-29').replace(/review: approved[\s\S]*/, 'review: pending');
    expect(() => parseLesson(`---\n${learned}\n---\nx`, '/k/sample-lesson.md', 'project')).toThrow(/quote/);
  });

  it('requires a reviewer on approved lessons', () => {
    const noReviewer = META.replace('reviewed_by: someone\n', '');
    expect(() => parseLesson(`---\n${noReviewer}\n---\nx`, '/k/sample-lesson.md', 'global')).toThrow(/reviewed_by/);
  });

  it('requires the id to match the file name', () => {
    expect(() => parseLesson(`---\n${META}\n---\nx`, '/k/other.md', 'global')).toThrow(/file name/);
  });

  it('names the file when the YAML is broken', () => {
    expect(() => parseLesson('---\nid: [unclosed\n---\nx', '/k/sample-lesson.md', 'global')).toThrow(/sample-lesson\.md: invalid YAML/);
  });

  it('round-trips through serializeLesson', () => {
    const l = parseLesson(`---\n${META}\n---\nBody text.\n`, '/k/sample-lesson.md', 'global');
    const { body, file: _f, layer: _l, ...meta } = l;
    expect(parseLesson(serializeLesson(meta, body), '/k/sample-lesson.md', 'global')).toEqual(l);
  });
});
