import { describe, expect, it } from 'vitest';
import { createStyle } from '../../src/ui/style.js';

describe('createStyle', () => {
  it('colours a terminal', () => {
    const s = createStyle({ isTTY: true }, {});
    expect(s.enabled).toBe(true);
    expect(s.red('x')).toBe('\u001b[31mx\u001b[39m');
  });
  it('is plain without a terminal or with NO_COLOR set', () => {
    expect(createStyle({ isTTY: false }, {}).red('x')).toBe('x');
    expect(createStyle({ isTTY: true }, { NO_COLOR: '1' }).enabled).toBe(false);
    expect(createStyle({ isTTY: true }, { NO_COLOR: '' }).enabled).toBe(true);
  });
});
