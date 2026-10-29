import type { AnyCheckType } from './check-type.js';
import { codeDependenciesCheck } from './types/code-dependencies.js';
import { codeSecretsCheck } from './types/code-secrets.js';
import { dnsDanglingCheck } from './types/dns-dangling.js';
import { exposedPathCheck } from './types/exposed-path.js';
import { headerBudgetCheck } from './types/header-budget.js';
import { hostConfigCheck } from './types/host-config.js';
import { hostPackageCheck } from './types/host-package.js';
import { httpCookieCheck } from './types/http-cookie.js';
import { httpCorsCheck } from './types/http-cors.js';
import { httpHeaderCheck } from './types/http-header.js';
import { httpRedirectCheck } from './types/http-redirect.js';
import { lbBypassCheck } from './types/lb-bypass.js';
import { portExposureCheck } from './types/port-exposure.js';
import { tlsCheck } from './types/tls.js';

/** Every check type the engine knows. Learning may add YAML instances of these types, never new types. */
const ALL: AnyCheckType[] = [
  httpRedirectCheck,
  httpHeaderCheck,
  httpCookieCheck,
  httpCorsCheck,
  headerBudgetCheck,
  hostConfigCheck,
  hostPackageCheck,
  exposedPathCheck,
  tlsCheck,
  portExposureCheck,
  lbBypassCheck,
  dnsDanglingCheck,
  codeSecretsCheck,
  codeDependenciesCheck,
];

export const CHECK_TYPES: ReadonlyMap<string, AnyCheckType> = new Map(ALL.map((t) => [t.type, t]));
