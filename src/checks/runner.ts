import { NetError } from '../net/errors.js';
import { ScopeError } from '../project/scope.js';
import type { CheckResult } from '../types.js';
import type { CheckInstance } from './catalog.js';
import type { AnyCheckType } from './check-type.js';
import { ObservationError } from './errors.js';
import { subjectId, subjectKind, type CheckContext, type CheckSubject } from './context.js';

export function applicableInstances(instances: readonly CheckInstance[], subject: CheckSubject): CheckInstance[] {
  const kind = subjectKind(subject);
  return instances.filter((i) => i.applies_to.includes(kind));
}

export async function runInstance(
  ctx: CheckContext,
  subject: CheckSubject,
  instance: CheckInstance,
  types: ReadonlyMap<string, AnyCheckType>,
): Promise<CheckResult> {
  const base = { check_id: instance.id, target: subjectId(subject), title: instance.title };
  const type = types.get(instance.type);
  if (!type) throw new Error(`Check type "${instance.type}" is not registered`);
  try {
    const out = await type.run(ctx, subject, instance.params, instance);
    return {
      ...base,
      outcome: out.outcome,
      severity: out.severity ?? instance.severity,
      observed: out.observed,
      evidence_id: out.evidence_id,
      ...(out.details ? { details: out.details } : {}),
    };
  } catch (e) {
    const message = e instanceof Error ? e.message : String(e);
    const label = ctx.project.network.scan_label;
    if (e instanceof ObservationError) {
      const observed = `${message} This does not mean the issue is fixed.`;
      const evidence_id = await ctx.evidence.put('note', base.target, observed, { code: e.code, message, scan_label: label });
      return { ...base, outcome: 'unverifiable', severity: instance.severity, observed, evidence_id };
    }
    const unverifiable = e instanceof NetError || e instanceof ScopeError;
    const code = e instanceof NetError ? e.code : e instanceof ScopeError ? 'OUT_OF_SCOPE' : 'CHECK_ERROR';
    const reach =
      subject.kind === 'host' && subject.host.reachable_from.length > 0
        ? ` Expected to be reachable from: ${subject.host.reachable_from.join(', ')}.`
        : '';
    const observed = unverifiable
      ? `Could not observe (${code}) from network "${label}": ${message}.${reach} A timeout or refusal here does not mean the issue is fixed.`
      : `Check failed to run: ${message}`;
    const evidence_id = await ctx.evidence.put('note', base.target, observed, { code, message, scan_label: label });
    return { ...base, outcome: unverifiable ? 'unverifiable' : 'error', severity: instance.severity, observed, evidence_id };
  }
}

/** Runs applicable instances one at a time: polite to targets, deterministic evidence order. */
export async function runChecks(
  ctx: CheckContext,
  subject: CheckSubject,
  instances: readonly CheckInstance[],
  types: ReadonlyMap<string, AnyCheckType>,
  onResult?: (result: CheckResult) => void,
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  for (const instance of applicableInstances(instances, subject)) {
    const result = await runInstance(ctx, subject, instance, types);
    results.push(result);
    onResult?.(result);
  }
  return results;
}
