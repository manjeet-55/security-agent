import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { PACKAGE_ROOT, projectStateDir } from '../src/paths.js';

describe('paths', () => {
  it('resolves the package root (the folder holding package.json)', () => {
    expect(existsSync(path.join(PACKAGE_ROOT, 'package.json'))).toBe(true);
  });
  it('keeps project state under .secagent', () => {
    expect(projectStateDir('/work/app')).toBe(path.join('/work/app', '.secagent'));
  });
});
