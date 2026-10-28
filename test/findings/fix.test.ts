import { describe, expect, it } from 'vitest';
import { CheckInstanceSchema } from '../../src/checks/catalog.js';
import { selectFix } from '../../src/findings/fix.js';

const instance = CheckInstanceSchema.parse({
  id: 'hdr-hsts',
  type: 'http_header',
  title: 'HSTS',
  severity: 'medium',
  applies_to: ['web'],
  fix_hints: { nginx: 'add_header ...', express: 'helmet.hsts()', any: 'general advice' },
  side_effects: ['header-budget-proxy-buffer'],
  source_url: 'https://example.com/guide',
  review: 'approved',
});

describe('selectFix', () => {
  it('keeps hints matching the stack plus "any"', () => {
    expect(selectFix(instance, { proxy: 'nginx', frontend: 'angular' })).toEqual({
      where: 'nginx, any',
      how: '[nginx] add_header ...\n[any] general advice',
      side_effects: ['header-budget-proxy-buffer'],
    });
  });
  it('falls back to every hint when the stack is unknown', () => {
    expect(selectFix({ ...instance, fix_hints: { nginx: 'n', express: 'e' } }, {}).where).toBe('nginx, express');
  });
});
