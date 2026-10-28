import type { z } from 'zod';
import type { Outcome, Severity, SubjectKind } from '../types.js';
import type { CheckInstance } from './catalog.js';
import type { CheckContext, CheckSubject } from './context.js';

export interface CheckOutput {
  outcome: Outcome;
  observed: string;
  evidence_id: string;
  /** Overrides the instance's default severity for this result. */
  severity?: Severity;
  details?: Record<string, unknown>;
}

export interface CheckType<P> {
  type: string;
  /** Subject kinds this type can run against; instances choose a subset with applies_to. */
  supports: readonly SubjectKind[];
  params: z.ZodType<P>;
  run(ctx: CheckContext, subject: CheckSubject, params: P, instance: CheckInstance): Promise<CheckOutput>;
}

/** Each type validates its own params, so the registry stores them without a shared params type. */
export type AnyCheckType = CheckType<any>;
