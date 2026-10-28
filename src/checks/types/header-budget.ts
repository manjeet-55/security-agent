import { z } from 'zod';
import type { HttpObservation } from '../../net/http.js';
import type { Severity } from '../../types.js';
import type { CheckType } from '../check-type.js';
import { getPage } from '../context.js';

export const headerBudgetParams = z
  .object({
    warn_bytes: z.number().int().positive().default(3072),
    high_bytes: z.number().int().positive().default(4096),
  })
  .refine((p) => p.warn_bytes < p.high_bytes, { message: 'warn_bytes must be below high_bytes' });
export type HeaderBudgetParams = z.infer<typeof headerBudgetParams>;

const NOTE = 'Measured on an unauthenticated response; logged-in responses that set session cookies are larger.';

export function evaluateBudget(
  obs: HttpObservation,
  p: HeaderBudgetParams,
): { outcome: 'pass' | 'fail'; observed: string; severity?: Severity } {
  const bytes = obs.headerBytes;
  if (bytes >= p.high_bytes) {
    return {
      outcome: 'fail',
      severity: 'high',
      observed: `${bytes} bytes of response headers, at or over ${p.high_bytes} (a common proxy buffer default, e.g. nginx proxy_buffer_size 4k, answers 502 beyond it). ${NOTE}`,
    };
  }
  if (bytes >= p.warn_bytes) {
    return { outcome: 'fail', observed: `${bytes} bytes of response headers, within ${p.high_bytes - bytes} bytes of ${p.high_bytes}. ${NOTE}` };
  }
  return { outcome: 'pass', observed: `${bytes} bytes of response headers (${p.high_bytes - bytes} bytes below ${p.high_bytes}). ${NOTE}` };
}

export const headerBudgetCheck: CheckType<HeaderBudgetParams> = {
  type: 'header_budget',
  supports: ['web', 'api'],
  params: headerBudgetParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'target') throw new Error('header_budget runs on targets only');
    const page = await getPage(ctx, subject);
    return { ...evaluateBudget(page.obs, p), evidence_id: page.evidenceId };
  },
};
