import { describe, expect, it } from 'vitest';
import { evaluateHeader, httpHeaderCheck, httpHeaderParams, parseCsp } from '../../../src/checks/types/http-header.js';
import { fakeObs, makeCtx, targetSubject } from '../../helpers/ctx.js';

const params = (p: Record<string, unknown>) => httpHeaderParams.parse(p);
const withHeaders = (headers: Record<string, string>) => fakeObs({ headers });

describe('parseCsp', () => {
  it('maps lowercased directives to their sources', () => {
    const csp = parseCsp("Default-Src 'self'; script-src 'self' cdn.example.com;;");
    expect(csp.get('default-src')).toEqual(["'self'"]);
    expect(csp.get('script-src')).toEqual(["'self'", 'cdn.example.com']);
  });
});

describe('evaluateHeader', () => {
  const hsts = params({ header: 'Strict-Transport-Security', must_exist: true, min_max_age: 15552000 });

  it('lowercases the header name', () => {
    expect(hsts.header).toBe('strict-transport-security');
  });

  it('fails a missing required header', () => {
    expect(evaluateHeader(withHeaders({}), hsts)).toEqual({ outcome: 'fail', observed: 'strict-transport-security header is missing' });
  });

  it('checks HSTS max-age', () => {
    expect(evaluateHeader(withHeaders({ 'strict-transport-security': 'max-age=300' }), hsts).outcome).toBe('fail');
    expect(evaluateHeader(withHeaders({ 'strict-transport-security': 'max-age=31536000; includeSubDomains' }), hsts).outcome).toBe('pass');
  });

  it('accepts CSP frame-ancestors in place of X-Frame-Options', () => {
    const xfo = params({ header: 'x-frame-options', must_exist: true, one_of: ['deny', 'sameorigin'], satisfied_by_csp_directive: 'frame-ancestors' });
    expect(evaluateHeader(withHeaders({ 'content-security-policy': "frame-ancestors 'none'" }), xfo).outcome).toBe('pass');
    expect(evaluateHeader(withHeaders({}), xfo).outcome).toBe('fail');
    expect(evaluateHeader(withHeaders({ 'x-frame-options': 'ALLOW-FROM x' }), xfo).outcome).toBe('fail');
    expect(evaluateHeader(withHeaders({ 'x-frame-options': 'DENY' }), xfo).outcome).toBe('pass');
  });

  describe('CSP script restrictions', () => {
    const csp = params({
      header: 'content-security-policy',
      must_exist: true,
      csp_forbid: { directive: 'script-src', fallback: 'default-src', tokens: ["'unsafe-inline'", "'unsafe-eval'", '*', 'https:'] },
    });
    it('fails unsafe-inline in script-src', () => {
      const v = evaluateHeader(withHeaders({ 'content-security-policy': "default-src 'self'; script-src 'self' 'unsafe-inline'" }), csp);
      expect(v).toEqual({ outcome: 'fail', observed: "Content-Security-Policy script-src allows 'unsafe-inline'" });
    });
    it("ignores 'unsafe-inline' when a nonce or hash is present (browsers ignore it then)", () => {
      expect(evaluateHeader(withHeaders({ 'content-security-policy': "script-src 'self' 'unsafe-inline' 'nonce-abc'" }), csp).outcome).toBe('pass');
    });
    it('falls back to default-src', () => {
      expect(evaluateHeader(withHeaders({ 'content-security-policy': 'default-src *' }), csp).observed).toContain('default-src allows *');
    });
    it('fails when neither directive is set', () => {
      expect(evaluateHeader(withHeaders({ 'content-security-policy': "frame-ancestors 'none'" }), csp).observed).toContain('unrestricted');
    });
  });

  it('fails a header that must not be sent', () => {
    const p = params({ header: 'x-powered-by', must_not_exist: true });
    expect(evaluateHeader(withHeaders({ 'x-powered-by': 'Express' }), p).outcome).toBe('fail');
    expect(evaluateHeader(withHeaders({}), p).outcome).toBe('pass');
  });

  it('fails a Server header that discloses a version', () => {
    const p = params({ header: 'server', forbid_pattern: '\\d' });
    expect(evaluateHeader(withHeaders({ server: 'nginx/1.30.6' }), p).outcome).toBe('fail');
    expect(evaluateHeader(withHeaders({ server: 'nginx' }), p).outcome).toBe('pass');
  });

  it('compares equals case-insensitively', () => {
    const p = params({ header: 'x-content-type-options', must_exist: true, equals: 'nosniff' });
    expect(evaluateHeader(withHeaders({ 'x-content-type-options': 'NOSNIFF' }), p).outcome).toBe('pass');
  });

  it('rejects contradictory params', () => {
    expect(httpHeaderParams.safeParse({ header: 'x', must_exist: true, must_not_exist: true }).success).toBe(false);
  });
});

describe('http_header check', () => {
  it('evaluates the shared page observation', async () => {
    const { ctx } = await makeCtx({ http: async (url) => fakeObs({ url, headers: { 'x-content-type-options': 'nosniff' } }) });
    const out = await httpHeaderCheck.run(ctx, targetSubject(ctx), params({ header: 'x-content-type-options', must_exist: true, equals: 'nosniff' }), {} as never);
    expect(out.outcome).toBe('pass');
    expect(out.evidence_id).toMatch(/^ev_/);
  });
});
