import { describe, expect, it } from 'vitest';
import { loadCheckInstances } from '../../src/checks/catalog.js';
import { CHECK_TYPES } from '../../src/checks/registry.js';
import { GLOBAL_CHECKS_DIR } from '../../src/paths.js';

describe('seed check catalog', () => {
  it('loads every seed instance against the registered types', async () => {
    const instances = await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES);
    expect(instances.length).toBeGreaterThan(0);
    for (const i of instances) {
      expect(i.review).toBe('approved');
      expect(i.added_by).toBe('seed');
      const type = CHECK_TYPES.get(i.type);
      expect(type).toBeDefined();
      for (const kind of i.applies_to) expect(type?.supports).toContain(kind);
    }
  });

  it('explains every seed check in plain words for the report', async () => {
    const instances = await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES);
    const missing = instances.filter((i) => !i.why).map((i) => i.id);
    expect(missing).toEqual([]);
    for (const i of instances) {
      expect(i.why?.length, i.id).toBeGreaterThanOrEqual(40);
      expect(i.why?.length, i.id).toBeLessThanOrEqual(300);
    }
  });
});
