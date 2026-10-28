import { z } from 'zod';
import type { HttpObservation } from '../../net/http.js';
import type { CheckType } from '../check-type.js';
import { getPage } from '../context.js';

export const httpHeaderParams = z
  .object({
    header: z
      .string()
      .min(1)
      .transform((h) => h.toLowerCase()),
    must_exist: z.boolean().default(false),
    must_not_exist: z.boolean().default(false),
    equals: z.string().optional(),
    one_of: z.array(z.string()).min(1).optional(),
    min_max_age: z.number().int().positive().optional(),
    csp_forbid: z
      .object({ directive: z.string(), fallback: z.string().optional(), tokens: z.array(z.string()).min(1) })
      .optional(),
    forbid_pattern: z.string().optional(),
    satisfied_by_csp_directive: z.string().optional(),
  })
  .refine((p) => !(p.must_exist && p.must_not_exist), { message: 'must_exist and must_not_exist are mutually exclusive' });
export type HttpHeaderParams = z.infer<typeof httpHeaderParams>;

export function parseCsp(value: string): Map<string, string[]> {
  const directives = new Map<string, string[]>();
  for (const part of value.split(';')) {
    const [name, ...sources] = part.trim().split(/\s+/);
    if (name && !directives.has(name.toLowerCase())) directives.set(name.toLowerCase(), sources);
  }
  return directives;
}

const HASH_OR_NONCE = /^'(nonce-|sha256-|sha384-|sha512-)/i;

function shown(value: string): string {
  return value.length > 160 ? `${value.slice(0, 157)}...` : value;
}

export function evaluateHeader(obs: HttpObservation, p: HttpHeaderParams): { outcome: 'pass' | 'fail'; observed: string } {
  const raw = obs.headers[p.header];
  if (raw === undefined) {
    if (p.satisfied_by_csp_directive) {
      const csp = obs.headers['content-security-policy'];
      if (csp !== undefined && parseCsp(csp).has(p.satisfied_by_csp_directive)) {
        return { outcome: 'pass', observed: `${p.header} absent, but Content-Security-Policy ${p.satisfied_by_csp_directive} covers it` };
      }
    }
    return p.must_exist
      ? { outcome: 'fail', observed: `${p.header} header is missing` }
      : { outcome: 'pass', observed: `${p.header} header is absent` };
  }

  const value = raw.trim();
  if (p.must_not_exist) {
    return { outcome: 'fail', observed: `${p.header}: ${shown(value)} (should not be sent; it discloses implementation details)` };
  }
  if (p.equals !== undefined && value.toLowerCase() !== p.equals.toLowerCase()) {
    return { outcome: 'fail', observed: `${p.header}: ${shown(value)} (expected "${p.equals}")` };
  }
  if (p.one_of !== undefined && !p.one_of.some((o) => o.toLowerCase() === value.toLowerCase())) {
    return { outcome: 'fail', observed: `${p.header}: ${shown(value)} (expected one of ${p.one_of.join(', ')})` };
  }
  if (p.min_max_age !== undefined) {
    const match = /max-age\s*=\s*"?(\d+)"?/i.exec(value)?.[1];
    const age = match !== undefined ? Number(match) : Number.NaN;
    if (!(age >= p.min_max_age)) {
      return { outcome: 'fail', observed: `${p.header}: ${shown(value)} (max-age must be at least ${p.min_max_age})` };
    }
  }
  if (p.csp_forbid !== undefined) {
    const { directive, fallback, tokens } = p.csp_forbid;
    const csp = parseCsp(value);
    const used = csp.has(directive) ? directive : fallback !== undefined && csp.has(fallback) ? fallback : undefined;
    if (used === undefined) {
      return {
        outcome: 'fail',
        observed: `Content-Security-Policy sets neither ${directive}${fallback ? ` nor ${fallback}` : ''}, so script sources are unrestricted`,
      };
    }
    const sources = csp.get(used) ?? [];
    const hasHashOrNonce = sources.some((s) => HASH_OR_NONCE.test(s));
    const bad = sources.filter(
      (s) => tokens.includes(s.toLowerCase()) && !(hasHashOrNonce && s.toLowerCase() === "'unsafe-inline'"),
    );
    if (bad.length > 0) return { outcome: 'fail', observed: `Content-Security-Policy ${used} allows ${bad.join(' ')}` };
  }
  if (p.forbid_pattern !== undefined && new RegExp(p.forbid_pattern).test(value)) {
    return { outcome: 'fail', observed: `${p.header}: ${shown(value)} (matches forbidden pattern ${p.forbid_pattern})` };
  }
  return { outcome: 'pass', observed: `${p.header}: ${shown(value)}` };
}

export const httpHeaderCheck: CheckType<HttpHeaderParams> = {
  type: 'http_header',
  supports: ['web', 'api'],
  params: httpHeaderParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'target') throw new Error('http_header runs on targets only');
    const page = await getPage(ctx, subject);
    return { ...evaluateHeader(page.obs, p), evidence_id: page.evidenceId };
  },
};
