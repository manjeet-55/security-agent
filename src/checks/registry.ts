import type { AnyCheckType } from './check-type.js';
import { httpHeaderCheck } from './types/http-header.js';
import { httpRedirectCheck } from './types/http-redirect.js';

/** Every check type the engine knows. Learning may add YAML instances of these types, never new types. */
const ALL: AnyCheckType[] = [httpRedirectCheck, httpHeaderCheck];

export const CHECK_TYPES: ReadonlyMap<string, AnyCheckType> = new Map(ALL.map((t) => [t.type, t]));
