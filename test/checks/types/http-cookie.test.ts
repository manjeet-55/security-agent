import { describe, expect, it } from 'vitest';
import { evaluateCookies, httpCookieParams } from '../../../src/checks/types/http-cookie.js';
import { parseSetCookie } from '../../../src/net/http.js';
import { fakeObs } from '../../helpers/ctx.js';

const P = httpCookieParams.parse({});
const cookies = (...lines: string[]) => fakeObs({ setCookies: lines.map(parseSetCookie) });

describe('evaluateCookies', () => {
  it('passes when no cookies are set', () => {
    expect(evaluateCookies(fakeObs(), P)).toEqual({ outcome: 'pass', observed: 'no cookies set on this response' });
  });
  it('passes when every cookie has Secure, HttpOnly and SameSite', () => {
    expect(evaluateCookies(cookies('sid=x; Secure; HttpOnly; SameSite=Lax'), P).outcome).toBe('pass');
  });
  it('lists each cookie and the flags it is missing', () => {
    expect(evaluateCookies(cookies('sid=x; Secure', 'theme=dark; Secure; HttpOnly; SameSite=Strict'), P)).toEqual({
      outcome: 'fail',
      observed: 'sid missing httponly, samesite',
    });
  });
  it('can require a subset of flags', () => {
    expect(evaluateCookies(cookies('sid=x; Secure'), httpCookieParams.parse({ require: ['secure'] })).outcome).toBe('pass');
  });
  it('labels a nameless cookie (unnamed) and never echoes its value', () => {
    const result = evaluateCookies(cookies('s3cr3t; Path=/'), P);
    expect(result.observed).toContain('(unnamed)');
    expect(result.observed).not.toContain('s3cr3t');
  });
});
