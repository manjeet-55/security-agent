import { describe, expect, it } from 'vitest';
import { evaluateDirect } from '../../../src/checks/types/lb-bypass.js';

describe('evaluateDirect', () => {
  it('fails when the server answers on its own address', () => {
    expect(evaluateDirect([{ url: 'https://198.51.100.7/', status: 200 }, { url: 'http://198.51.100.7/', code: 'ECONNREFUSED' }], 'office').outcome).toBe('fail');
  });
  it('passes when both ports refuse', () => {
    expect(evaluateDirect([{ url: 'https://x/', code: 'ECONNREFUSED' }, { url: 'http://x/', code: 'ECONNREFUSED' }], 'office').outcome).toBe('pass');
  });
  it('is unverifiable on a timeout, which proves nothing from this network', () => {
    expect(evaluateDirect([{ url: 'https://x/', code: 'ETIMEDOUT' }, { url: 'http://x/', code: 'ECONNREFUSED' }], 'office').outcome).toBe('unverifiable');
  });
});
