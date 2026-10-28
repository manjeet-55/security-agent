import type { CheckInstance } from '../checks/catalog.js';
import type { Stack } from '../project/schema.js';

/** Picks fix hints whose key matches a stack value (plus "any"); with no match, shows all hints. */
export function selectFix(instance: CheckInstance, stack: Stack): { where: string; how: string; side_effects: string[] } {
  const stackValues = new Set(Object.values(stack).filter((v): v is string => typeof v === 'string'));
  const keys = Object.keys(instance.fix_hints);
  const matched = keys.filter((k) => stackValues.has(k));
  const chosen = matched.length > 0 ? [...matched, ...keys.filter((k) => k === 'any')] : keys;
  return {
    where: chosen.join(', ') || 'unspecified',
    how: chosen.map((k) => `[${k}] ${instance.fix_hints[k]}`).join('\n'),
    side_effects: instance.side_effects,
  };
}
