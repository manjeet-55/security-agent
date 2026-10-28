import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { CatalogError, loadCheckInstances } from '../../src/checks/catalog.js';
import type { AnyCheckType } from '../../src/checks/check-type.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

const fake: AnyCheckType = {
  type: 'fake',
  supports: ['web'],
  params: z.object({ limit: z.number().default(5) }),
  run: async () => {
    throw new Error('not run in catalog tests');
  },
};
const TYPES = new Map([['fake', fake]]);

const instance = (extra = '') => `id: fake-one
type: fake
title: Fake check
severity: low
applies_to: [web]
source_url: https://example.com/guide
review: approved
${extra}`;

describe('loadCheckInstances', () => {
  it('loads instances and applies the type param defaults', async () => {
    const dir = await tempDir();
    await writeFiles(dir, { 'fake-one.yaml': instance(), 'README.md': 'ignored' });
    const [one] = await loadCheckInstances(dir, TYPES);
    expect(one).toMatchObject({ id: 'fake-one', params: { limit: 5 }, added_by: 'seed', fix_hints: {}, side_effects: [] });
  });

  it('collects every problem into one CatalogError', async () => {
    const dir = await tempDir();
    await writeFiles(dir, {
      'a.yaml': instance().replace('type: fake', 'type: nope'),
      'b.yaml': instance('params:\n  limit: "five"\n').replace('fake-one', 'fake-two'),
      'c.yaml': `${instance().replace('fake-one', 'fake-three')}added_by: learn-2026-10-28\n`,
    });
    const err = await loadCheckInstances(dir, TYPES).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CatalogError);
    const message = (err as Error).message;
    expect(message).toContain('a.yaml: unknown check type "nope"');
    expect(message).toContain('b.yaml: params.limit');
    expect(message).toContain('c.yaml: quote');
  });

  it('rejects duplicate ids', async () => {
    const dir = await tempDir();
    await writeFiles(dir, { 'a.yaml': instance(), 'b.yaml': instance() });
    await expect(loadCheckInstances(dir, TYPES)).rejects.toThrow(/duplicate check id "fake-one"/);
  });
});
