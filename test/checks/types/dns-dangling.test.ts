import { describe, expect, it } from 'vitest';
import { evaluateChain } from '../../../src/checks/types/dns-dangling.js';

describe('evaluateChain', () => {
  it('passes without a CNAME or when the chain resolves, fails when it ends in a name that does not exist', () => {
    expect(evaluateChain('app.example.com', { chain: [], dangling: false }).outcome).toBe('pass');
    expect(evaluateChain('app.example.com', { chain: ['x.cloudfront.net'], dangling: false }).outcome).toBe('pass');
    const f = evaluateChain('old.example.com', { chain: ['shop-old.azurewebsites.net'], dangling: true });
    expect(f.outcome).toBe('fail');
    expect(f.observed).toContain('shop-old.azurewebsites.net does not exist');
  });
});
