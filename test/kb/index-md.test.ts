import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { expect, it } from 'vitest';
import { loadCheckInstances } from '../../src/checks/catalog.js';
import { CHECK_TYPES } from '../../src/checks/registry.js';
import { renderIndex } from '../../src/kb/index-md.js';
import { loadLessons } from '../../src/kb/store.js';
import { GLOBAL_CHECKS_DIR, GLOBAL_KNOWLEDGE_DIR, GLOBAL_LESSONS_DIR } from '../../src/paths.js';

it('knowledge/INDEX.md is current (regenerate with: npx tsx src/cli.ts kb index)', async () => {
  const expected = renderIndex(await loadLessons({ global: GLOBAL_LESSONS_DIR }), await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES));
  expect(await readFile(path.join(GLOBAL_KNOWLEDGE_DIR, 'INDEX.md'), 'utf8')).toBe(expected);
});
