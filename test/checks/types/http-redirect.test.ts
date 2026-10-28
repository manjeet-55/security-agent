import { describe, expect, it } from 'vitest';
import { evaluateRedirect, httpRedirectCheck, httpRedirectParams } from '../../../src/checks/types/http-redirect.js';
import { NetError } from '../../../src/net/errors.js';
import { fakeObs, makeCtx, targetSubject } from '../../helpers/ctx.js';

const P = httpRedirectParams.parse({});
const at = (status: number, location?: string) =>
  fakeObs({ url: 'http://app.example.com/', status, ...(location ? { location } : {}) });

describe('evaluateRedirect', () => {
  it('passes a permanent redirect to https on the same host', () => {
    expect(evaluateRedirect(at(301, 'https://app.example.com/'), 'app.example.com', P).outcome).toBe('pass');
    expect(evaluateRedirect(at(308, 'https://app.example.com/'), 'app.example.com', P).outcome).toBe('pass');
  });
  it('fails when content is served over plain http', () => {
    const v = evaluateRedirect(at(200), 'app.example.com', P);
    expect(v.outcome).toBe('fail');
    expect(v.observed).toContain('plaintext');
  });
  it('fails a temporary redirect', () => {
    expect(evaluateRedirect(at(302, 'https://app.example.com/'), 'app.example.com', P).observed).toContain('302');
  });
  it('fails a redirect to a different host', () => {
    expect(evaluateRedirect(at(301, 'https://login.example.net/'), 'app.example.com', P).observed).toContain('different host');
  });
  it('fails a redirect that stays on http', () => {
    expect(evaluateRedirect(at(301, 'http://app.example.com/x'), 'app.example.com', P).observed).toContain('not https');
  });
});

describe('http_redirect check', () => {
  it('requests the http:// form of the target', async () => {
    const seen: string[] = [];
    const { ctx } = await makeCtx({
      http: async (url) => {
        seen.push(url);
        return fakeObs({ url, status: 308, location: 'https://app.example.com/' });
      },
    });
    const out = await httpRedirectCheck.run(ctx, targetSubject(ctx), P, {} as never);
    expect(seen).toEqual(['http://app.example.com/']);
    expect(out.outcome).toBe('pass');
  });

  it('passes when port 80 refuses connections', async () => {
    const { ctx } = await makeCtx({
      http: async () => {
        throw new NetError('ECONNREFUSED', 'refused');
      },
    });
    const out = await httpRedirectCheck.run(ctx, targetSubject(ctx), P, {} as never);
    expect(out.outcome).toBe('pass');
    expect(out.observed).toContain('refuses');
  });
});
