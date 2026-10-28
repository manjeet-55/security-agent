import { describe, expect, it } from 'vitest';
import { compareDebVersions } from '../../src/util/debver.js';

// Every vector was checked with `dpkg --compare-versions` on 2026-10-28.
const VECTORS: Array<[string, 'lt' | 'eq' | 'gt', string]> = [
  ['1:9.6p1-3ubuntu13.20', 'gt', '1:9.6p1-3ubuntu13.3'],
  ['1.0~rc1', 'lt', '1.0'],
  ['1.0+b1', 'gt', '1.0'],
  ['1:1.0', 'gt', '2.0'],
  ['2.30-1ubuntu1', 'gt', '2.30-1'],
  ['1.30.6-1~noble', 'lt', '1.30.6-1'],
  ['1.0a', 'lt', '1.0+'],
  ['1.0', 'eq', '1.0-0'],
  ['0:1.0', 'eq', '1.0'],
  ['1.2.3', 'lt', '1.2.10'],
  ['1.0~~', 'lt', '1.0~'],
  ['1.0-1', 'lt', '1.0.0-1'],
  ['8.9p1-3ubuntu0.18', 'gt', '8.9p1-3ubuntu0.10'],
  ['3.0.13-0ubuntu3.4', 'lt', '3.0.13-0ubuntu3.10'],
];

describe('compareDebVersions', () => {
  it.each(VECTORS)('%s %s %s', (a, rel, b) => {
    const r = compareDebVersions(a, b);
    expect(rel === 'lt' ? r < 0 : rel === 'gt' ? r > 0 : r === 0).toBe(true);
    const back = compareDebVersions(b, a);
    expect(rel === 'lt' ? back > 0 : rel === 'gt' ? back < 0 : back === 0).toBe(true);
  });
});
