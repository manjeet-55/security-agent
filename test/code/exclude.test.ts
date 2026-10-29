import { describe, expect, it } from 'vitest';
import { compileExcludes } from '../../src/code/exclude.js';

describe('compileExcludes', () => {
  const excluded = (patterns: string[], rel: string, isDir = false) => compileExcludes(patterns)(rel, isDir);

  it('excludes nothing with no patterns', () => {
    expect(excluded([], 'a/b.ts')).toBe(false);
  });
  it('matches a bare name at any depth, file or directory', () => {
    expect(excluded(['fixtures'], 'test/fixtures/a.txt')).toBe(true);
    expect(excluded(['secret.txt'], 'a/b/secret.txt')).toBe(true);
    expect(excluded(['secret.txt'], 'a/b/not-secret.txt')).toBe(false);
  });
  it('matches * within a segment and ** across segments', () => {
    expect(excluded(['*.sql'], 'db/dump.sql')).toBe(true);
    expect(excluded(['*.sql'], 'db/dump.sqlx')).toBe(false);
    expect(excluded(['docs/**/*.md'], 'docs/a/b/c.md')).toBe(true);
    expect(excluded(['docs/**/*.md'], 'docs/c.md')).toBe(true);
    expect(excluded(['docs/**/*.md'], 'other/docs/c.md')).toBe(false);
  });
  it('anchors patterns that contain a slash to the project root', () => {
    expect(excluded(['/vendor-src'], 'vendor-src/a.js')).toBe(true);
    expect(excluded(['/vendor-src'], 'x/vendor-src/a.js')).toBe(false);
    expect(excluded(['src/gen'], 'src/gen/a.ts')).toBe(true);
    expect(excluded(['src/gen'], 'other/src/gen/a.ts')).toBe(false);
  });
  it('treats a trailing slash as directories only', () => {
    expect(excluded(['build/'], 'build/out.js')).toBe(true);
    expect(excluded(['build/'], 'build', false)).toBe(false);
    expect(excluded(['build/'], 'build', true)).toBe(true);
  });
  it('treats ? as one non-slash character and escapes regex characters', () => {
    expect(excluded(['a?.txt'], 'ab.txt')).toBe(true);
    expect(excluded(['a?.txt'], 'a/.txt')).toBe(false);
    expect(excluded(['a+b.txt'], 'a+b.txt')).toBe(true);
    expect(excluded(['a+b.txt'], 'aab.txt')).toBe(false);
  });
  it('ignores blank lines and comments', () => {
    expect(excluded(['', '  ', '# note'], 'a.txt')).toBe(false);
  });
});
