# secagent Plan 1: Foundation, External Checks and `scan --no-ai`

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A working `secagent` CLI that creates a project's `.secagent/` folder, then runs deterministic, scope-guarded external checks against the targets and hosts the project lists, and writes evidence-backed findings. The checks are: HTTPS redirect, security headers, cookie flags, header size, exposed files, TLS and open ports.

**Architecture:**
- Network probes (`src/net/`) use only Node built-ins.
- Every probe goes through a `ScopedNet` client that refuses hosts not listed in `project.yaml`.
- Each check *type* is a TypeScript module with a zod params schema and a pure `evaluate*` function.
- Each check *instance* is a YAML file in `knowledge/checks/`.
- `scan --no-ai` runs every applicable instance and maps results to findings: fail → `open`, unverifiable → `unverifiable`, previously-open-now-pass → `fixed`. It stores evidence and a scan record, and computes new/fixed/regressed against the previous scan.

**Tech Stack:** TypeScript 6 (ESM, NodeNext), Node ≥ 22.12, zod 4, yaml 2, vitest 5, tsx; Docker Compose for the test lab.

**Spec:** `docs/superpowers/specs/2026-10-28-secagent-design.md`

**Roadmap.** This is plan 1 of 4. Later plans are written after this one is executed, so they build on real code.

| Plan | Scope (spec sections) |
|---|---|
| **1 (this)** | Scaffold, `project.yaml`, stack detection, `init`, scope guard, probes, evidence, check engine, 7 external check types with seed instances, findings, `scan --no-ai`, lab (§4.2–4.5, §6, §11 partial, §12–14 partial) |
| 2 | Host collector, parser, `host_config`, `host_package`, advisories (OSV/KEV/NVD/USN), `verify_claim` (§7, §8.2.1) |
| 3 | Knowledge base (lessons, INDEX, search/write guards, trust rule), MCP server and tools, `AGENTS.md` playbook, `init` MCP registration, report renderer (§5, §9, §10) |
| 4 | `fetch_source`, `sources.yaml`, `kb review`, `learn`, Claude plugin, `sec-researcher`, `eval`, stretch checks (§8, §9.4, §14.3) |

## Global Constraints

- **Runtime:**
  - Node `>=22.12` (`engines`), `"type": "module"`.
  - TypeScript `strict` + `noUncheckedIndexedAccess`, `module`/`moduleResolution` `NodeNext`.
  - Relative imports use the `.js` suffix.
- **Pinned dependencies** (exact, `--save-exact`):
  - runtime: `yaml@2.9.1`, `zod@4.6.7`
  - dev: `typescript@6.0.3`, `tsx@4.23.15`, `vitest@5.0.5`, `vite@8.3.5`, `@types/node@22.20.5`
- **No other runtime dependencies in this plan.** Probes use `node:http`, `node:https`, `node:tls`, `node:net` and `node:dns` only; no nmap or testssl.
- **Project-agnostic.** No client or project names, IPs or hostnames anywhere. Examples use `example.com`, `203.0.113.0/24` (TEST-NET-3) and the lab subnet `172.31.250.0/24`.
- **Scope.** Checks may reach the network **only** through the `NetClient` they're given (`ScopedNet` in production). Nothing else opens sockets.
- **Evidence** never stores cookie values or the contents of exposed files.
- **Defaults:**
  - timeouts: 5s connect, 10s total
  - one retry on `TIMEOUT`/`CONNECT_TIMEOUT` for HTTP and TLS (not TCP)
  - IPv4 (`network.ip_family: 4`)
  - port-probe concurrency ≤ 4 per host
  - `User-Agent: secagent/0.1 (+security self-assessment; authorised targets only)`
- **Commits:**
  - Conventional Commit messages, with **no** AI/assistant attribution lines.
  - The repo owner requires approval before commits. Get the go-ahead (batch approval for this plan is fine) before running any `git commit` step.
- **Testing:** run tests with `npx vitest run <path>`. Typecheck with `npx tsc -p tsconfig.json`.

## File Structure

```
secagent/
├─ package.json, tsconfig.json, tsconfig.build.json, vitest.config.ts, .gitignore
├─ src/
│  ├─ cli.ts                    CLI entry: init | scan --no-ai
│  ├─ types.ts                  Severity/Outcome/FindingStatus/SubjectKind, CheckResult, maxSeverity
│  ├─ paths.ts                  PACKAGE_ROOT, GLOBAL_CHECKS_DIR, projectStateDir
│  ├─ project/
│  │  ├─ schema.ts              project.yaml zod schema, validate/parse/load/save
│  │  ├─ stack.ts               detectStack (marker files, root + one level)
│  │  ├─ init.ts                initProject: .secagent/ tree, .gitignore, knowledge files, project.yaml
│  │  └─ scope.ts               Scope: hostname allowlist + private-address guard
│  ├─ net/
│  │  ├─ errors.ts              NetError, toNetError
│  │  ├─ ip.ts                  isPrivateAddress, resolveAddresses, stripBrackets
│  │  ├─ http.ts                httpRequest → HttpObservation (redacted cookies, header bytes)
│  │  ├─ tls.ts                 tlsHandshake → TlsObservation, isHandshakeRejection, cipher strings
│  │  ├─ tcp.ts                 tcpProbe → open|closed|timeout|unreachable
│  │  └─ scoped.ts              NetClient interface, ScopedNet, withRetry
│  ├─ evidence/store.ts         EvidenceStore, newEvidenceId, EVIDENCE_ID_PATTERN
│  ├─ checks/
│  │  ├─ context.ts             CheckContext, CheckSubject, memoize, getPage
│  │  ├─ check-type.ts          CheckType<P>, CheckOutput, AnyCheckType
│  │  ├─ catalog.ts             CheckInstanceSchema, loadCheckInstances
│  │  ├─ registry.ts            CHECK_TYPES
│  │  ├─ runner.ts              runInstance, runChecks (errors → unverifiable/error)
│  │  └─ types/                 http-redirect, http-header, http-cookie, header-budget,
│  │                            exposed-path, tls, port-exposure
│  ├─ findings/
│  │  ├─ schema.ts              CheckResultSchema, FindingSchema, ScanDiffSchema, ScanRecordSchema
│  │  ├─ ids.ts                 findingId, resultKey
│  │  ├─ diff.ts                diffScans
│  │  ├─ fix.ts                 selectFix (stack-aware fix_hints)
│  │  ├─ from-results.ts        resultsToFindings (--no-ai mapping)
│  │  └─ store.ts               FindingsStore (latest.json + history/)
│  ├─ scan/no-ai.ts             scanNoAi
│  └─ util/pool.ts              mapLimit
├─ knowledge/checks/*.yaml      16 seed check instances
├─ lab/                         docker-compose bad-site/good-site + lab project
└─ test/                        mirrors src/, plus helpers/ and fixtures/
```

---

### Task 1: Project scaffold and shared types

**Files:**
- Create: `package.json`, `tsconfig.json`, `tsconfig.build.json`, `vitest.config.ts`, `.gitignore`
- Create: `src/types.ts`, `src/paths.ts`
- Test: `test/types.test.ts`, `test/paths.test.ts`

**Interfaces:**
- Consumes: nothing
- Produces:
  - `SEVERITIES`, `Severity`, `SEVERITY_RANK`, `maxSeverity(list, fallback?)`
  - `OUTCOMES`, `Outcome`, `FINDING_STATUSES`, `FindingStatus`, `SUBJECT_KINDS`, `SubjectKind`
  - `interface CheckResult { check_id; target; title; outcome; severity; observed; evidence_id; details? }`
  - `PACKAGE_ROOT`, `GLOBAL_KNOWLEDGE_DIR`, `GLOBAL_CHECKS_DIR`, `SECAGENT_DIRNAME`, `projectStateDir(projectDir)`

- [ ] **Step 1: Write `package.json`**

```json
{
  "name": "secagent",
  "version": "0.1.0",
  "description": "Stack-agnostic security agent: deterministic probes and a per-project knowledge base, exposed over MCP",
  "type": "module",
  "bin": {
    "secagent": "dist/cli.js"
  },
  "files": [
    "dist",
    "knowledge",
    "agent"
  ],
  "engines": {
    "node": ">=22.12"
  },
  "scripts": {
    "build": "tsc -p tsconfig.build.json",
    "typecheck": "tsc -p tsconfig.json",
    "test": "vitest run",
    "dev": "tsx src/cli.ts"
  }
}
```

- [ ] **Step 2: Install pinned dependencies**

Run:
```bash
npm install --save-exact yaml@2.9.1 zod@4.6.7
npm install --save-exact --save-dev typescript@6.0.3 tsx@4.23.15 vitest@5.0.5 vite@8.3.5 @types/node@22.20.5
```
Expected: `package.json` gains `dependencies` and `devDependencies` with exact versions; `package-lock.json` is created.

- [ ] **Step 3: Write `tsconfig.json`, `tsconfig.build.json`, `vitest.config.ts`, `.gitignore`**

`tsconfig.json`:
```json
{
  "compilerOptions": {
    "target": "ES2023",
    "lib": ["ES2023"],
    "module": "NodeNext",
    "moduleResolution": "NodeNext",
    "strict": true,
    "noUncheckedIndexedAccess": true,
    "noImplicitOverride": true,
    "esModuleInterop": true,
    "skipLibCheck": true,
    "forceConsistentCasingInFileNames": true,
    "types": ["node"],
    "rootDir": ".",
    "noEmit": true
  },
  "include": ["src", "test", "vitest.config.ts"]
}
```

`tsconfig.build.json`:
```json
{
  "extends": "./tsconfig.json",
  "compilerOptions": {
    "noEmit": false,
    "rootDir": "src",
    "outDir": "dist"
  },
  "include": ["src"]
}
```

`vitest.config.ts`:
```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    testTimeout: 20_000,
  },
});
```

`.gitignore`:
```
node_modules/
dist/
lab/certs/
*.log
```

- [ ] **Step 4: Write the failing tests**

`test/types.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { maxSeverity, SEVERITY_RANK } from '../src/types.js';

describe('maxSeverity', () => {
  it('returns the most severe entry', () => {
    expect(maxSeverity(['low', 'high', 'medium'])).toBe('high');
  });
  it('returns the fallback for an empty list', () => {
    expect(maxSeverity([])).toBe('info');
    expect(maxSeverity([], 'low')).toBe('low');
  });
  it('ranks critical highest', () => {
    expect(SEVERITY_RANK.critical).toBeGreaterThan(SEVERITY_RANK.high);
  });
});
```

`test/paths.test.ts`:
```ts
import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { PACKAGE_ROOT, projectStateDir } from '../src/paths.js';

describe('paths', () => {
  it('resolves the package root (the folder holding package.json)', () => {
    expect(existsSync(path.join(PACKAGE_ROOT, 'package.json'))).toBe(true);
  });
  it('keeps project state under .secagent', () => {
    expect(projectStateDir('/work/app')).toBe(path.join('/work/app', '.secagent'));
  });
});
```

- [ ] **Step 5: Run the tests to verify they fail**

Run: `npx vitest run test/types.test.ts test/paths.test.ts`
Expected: FAIL, because `../src/types.js` and `../src/paths.js` can't be resolved.

- [ ] **Step 6: Implement `src/types.ts` and `src/paths.ts`**

`src/types.ts`:
```ts
export const SEVERITIES = ['critical', 'high', 'medium', 'low', 'info'] as const;
export type Severity = (typeof SEVERITIES)[number];

export const SEVERITY_RANK: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

export function maxSeverity(severities: readonly Severity[], fallback: Severity = 'info'): Severity {
  return severities.reduce<Severity>((max, s) => (SEVERITY_RANK[s] > SEVERITY_RANK[max] ? s : max), fallback);
}

export const OUTCOMES = ['pass', 'fail', 'unverifiable', 'error'] as const;
export type Outcome = (typeof OUTCOMES)[number];

export const FINDING_STATUSES = [
  'open',
  'fixed',
  'false_positive',
  'not_applicable',
  'accepted_risk',
  'unverifiable',
] as const;
export type FindingStatus = (typeof FINDING_STATUSES)[number];

export const SUBJECT_KINDS = ['web', 'api', 'host'] as const;
export type SubjectKind = (typeof SUBJECT_KINDS)[number];

/** One check instance run against one target or host. */
export interface CheckResult {
  check_id: string;
  /** Target id or host name. */
  target: string;
  title: string;
  outcome: Outcome;
  /** Effective severity for this result (a check may raise it above the instance default). */
  severity: Severity;
  /** One-line summary of what was observed. */
  observed: string;
  evidence_id: string;
  details?: Record<string, unknown>;
}
```

`src/paths.ts`:
```ts
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/** Root of the secagent package. src/paths.ts and dist/paths.js both sit one level below it. */
export const PACKAGE_ROOT = fileURLToPath(new URL('..', import.meta.url));
export const GLOBAL_KNOWLEDGE_DIR = path.join(PACKAGE_ROOT, 'knowledge');
export const GLOBAL_CHECKS_DIR = path.join(GLOBAL_KNOWLEDGE_DIR, 'checks');

export const SECAGENT_DIRNAME = '.secagent';

export function projectStateDir(projectDir: string): string {
  return path.join(projectDir, SECAGENT_DIRNAME);
}
```

- [ ] **Step 7: Run tests and typecheck**

Run: `npx vitest run test/types.test.ts test/paths.test.ts && npx tsc -p tsconfig.json`
Expected: 5 tests PASS; `tsc` exits 0 with no output.

- [ ] **Step 8: Commit**

```bash
git add package.json package-lock.json tsconfig.json tsconfig.build.json vitest.config.ts .gitignore src/types.ts src/paths.ts test/types.test.ts test/paths.test.ts
git commit -m "chore: scaffold secagent TypeScript project with shared types"
```

---

### Task 2: `project.yaml` schema

**Files:**
- Create: `src/project/schema.ts`, `test/helpers/tmp.ts`
- Test: `test/project/schema.test.ts`

**Interfaces:**
- Consumes: `projectStateDir` (Task 1)
- Produces:
  - `StackSchema`, `TargetSchema`, `HostSchema`, `ProjectSchema`
  - types `Stack`, `Target`, `Host`, `ProjectConfig`
  - `class ProjectConfigError extends Error`
  - `projectFile(projectDir): string`
  - `validateProject(raw: unknown, source?): ProjectConfig`
  - `parseProject(text: string, source?): ProjectConfig`
  - `loadProject(projectDir): Promise<ProjectConfig>`
  - `saveProject(projectDir, config): Promise<void>`
  - test helpers `tempDir(prefix?)`, `writeFiles(root, files)`

- [ ] **Step 1: Write the test helper and the failing tests**

`test/helpers/tmp.ts`:
```ts
import { mkdir, mkdtemp, writeFile } from 'node:fs/promises';
import os from 'node:os';
import path from 'node:path';

export function tempDir(prefix = 'secagent-'): Promise<string> {
  return mkdtemp(path.join(os.tmpdir(), prefix));
}

export async function writeFiles(root: string, files: Record<string, string>): Promise<void> {
  for (const [rel, content] of Object.entries(files)) {
    const full = path.join(root, rel);
    await mkdir(path.dirname(full), { recursive: true });
    await writeFile(full, content);
  }
}
```

`test/project/schema.test.ts`:
```ts
import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadProject, parseProject, ProjectConfigError, saveProject } from '../../src/project/schema.js';
import { tempDir } from '../helpers/tmp.js';

const VALID = `
version: 1
name: demo
targets:
  - id: portal
    url: https://portal.example.com
    type: web
    env: prod
hosts:
  - name: web-1
    address: 203.0.113.10
    env: prod
    serves: [portal]
`;

describe('project schema', () => {
  it('applies defaults', () => {
    const p = parseProject(VALID);
    expect(p.network).toEqual({ ip_family: 4, scan_label: 'unlabelled' });
    expect(p.stack).toEqual({});
    expect(p.targets[0]?.allow_private).toBe(false);
    expect(p.hosts[0]?.reachable_from).toEqual([]);
  });

  it('rejects non-http URLs', () => {
    expect(() => parseProject(VALID.replace('https://portal.example.com', 'ftp://portal.example.com'))).toThrow(
      /targets\.0\.url/,
    );
  });

  it('rejects duplicate target ids', () => {
    const dup = VALID.replace('hosts:', '  - id: portal\n    url: https://x.example.com\n    type: api\n    env: prod\nhosts:');
    expect(() => parseProject(dup)).toThrow(/duplicate target id "portal"/);
  });

  it('rejects serves entries that point at unknown targets', () => {
    expect(() => parseProject(VALID.replace('serves: [portal]', 'serves: [nope]'))).toThrow(/unknown target id "nope"/);
  });

  it('round-trips through save and load', async () => {
    const dir = await tempDir();
    await mkdir(path.join(dir, '.secagent'));
    const p = parseProject(VALID);
    await saveProject(dir, p);
    expect(await loadProject(dir)).toEqual(p);
  });

  it('explains a missing config', async () => {
    const dir = await tempDir();
    await expect(loadProject(dir)).rejects.toBeInstanceOf(ProjectConfigError);
    await expect(loadProject(dir)).rejects.toThrow(/secagent init/);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/project/schema.test.ts`
Expected: FAIL, because `../../src/project/schema.js` can't be resolved.

- [ ] **Step 3: Implement `src/project/schema.ts`**

```ts
import { readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { parse, stringify } from 'yaml';
import { z } from 'zod';
import { projectStateDir } from '../paths.js';

const Id = z
  .string()
  .regex(/^[a-z0-9][a-z0-9-]*$/, 'use lowercase letters, digits and dashes, starting with a letter or digit');

export const StackSchema = z.object({
  frontend: z.string().optional(),
  backend: z.string().optional(),
  proxy: z.string().optional(),
  hosting: z.string().optional(),
});

export const TargetSchema = z.object({
  id: Id,
  url: z.url({ protocol: /^https?$/ }),
  type: z.enum(['web', 'api']),
  env: z.string().min(1),
  allow_private: z.boolean().default(false),
});

export const HostSchema = z.object({
  name: Id,
  address: z.string().min(1),
  env: z.string().min(1),
  role: z.string().optional(),
  reachable_from: z.array(z.string()).default([]),
  serves: z.array(z.string()).default([]),
  allow_private: z.boolean().default(false),
});

export const ProjectSchema = z
  .object({
    version: z.literal(1),
    name: z.string().min(1),
    stack: StackSchema.default({}),
    network: z
      .object({
        ip_family: z.union([z.literal(4), z.literal(6)]).default(4),
        scan_label: z.string().min(1).default('unlabelled'),
      })
      .prefault({}),
    targets: z.array(TargetSchema).default([]),
    hosts: z.array(HostSchema).default([]),
  })
  .superRefine((p, ctx) => {
    const targetIds = new Set<string>();
    p.targets.forEach((t, i) => {
      if (targetIds.has(t.id)) {
        ctx.addIssue({ code: 'custom', path: ['targets', i, 'id'], message: `duplicate target id "${t.id}"` });
      }
      targetIds.add(t.id);
    });
    const hostNames = new Set<string>();
    p.hosts.forEach((h, i) => {
      if (hostNames.has(h.name)) {
        ctx.addIssue({ code: 'custom', path: ['hosts', i, 'name'], message: `duplicate host name "${h.name}"` });
      }
      hostNames.add(h.name);
      for (const s of h.serves) {
        if (!targetIds.has(s)) {
          ctx.addIssue({ code: 'custom', path: ['hosts', i, 'serves'], message: `unknown target id "${s}"` });
        }
      }
    });
  });

export type Stack = z.infer<typeof StackSchema>;
export type Target = z.infer<typeof TargetSchema>;
export type Host = z.infer<typeof HostSchema>;
export type ProjectConfig = z.infer<typeof ProjectSchema>;

export class ProjectConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ProjectConfigError';
  }
}

export function projectFile(projectDir: string): string {
  return path.join(projectStateDir(projectDir), 'project.yaml');
}

export function validateProject(raw: unknown, source = 'project.yaml'): ProjectConfig {
  const result = ProjectSchema.safeParse(raw);
  if (!result.success) {
    const lines = result.error.issues.map((i) => `  - ${i.path.join('.') || '(root)'}: ${i.message}`);
    throw new ProjectConfigError(`${source} is invalid:\n${lines.join('\n')}`);
  }
  return result.data;
}

export function parseProject(text: string, source = 'project.yaml'): ProjectConfig {
  let raw: unknown;
  try {
    raw = parse(text);
  } catch (e) {
    throw new ProjectConfigError(`${source}: invalid YAML: ${(e as Error).message}`);
  }
  return validateProject(raw, source);
}

export async function loadProject(projectDir: string): Promise<ProjectConfig> {
  const file = projectFile(projectDir);
  let text: string;
  try {
    text = await readFile(file, 'utf8');
  } catch {
    throw new ProjectConfigError(`No project config at ${file}. Run "secagent init" first.`);
  }
  return parseProject(text, file);
}

const HEADER = '# secagent project config. Targets and hosts listed here are the ONLY things secagent will probe.\n';

export async function saveProject(projectDir: string, config: ProjectConfig): Promise<void> {
  const valid = validateProject(config);
  await writeFile(projectFile(projectDir), HEADER + stringify(valid), 'utf8');
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/project/schema.test.ts && npx tsc -p tsconfig.json`
Expected: 6 tests PASS; `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/project/schema.ts test/helpers/tmp.ts test/project/schema.test.ts
git commit -m "feat(project): add project.yaml schema with load/save"
```

---

### Task 3: Stack detection

**Files:**
- Create: `src/project/stack.ts`
- Test: `test/project/stack.test.ts`

**Interfaces:**
- Consumes: type `Stack` (Task 2); test helpers `tempDir`, `writeFiles` (Task 2)
- Produces: `interface StackDetection { stack: Stack; markers: string[] }`, `detectStack(projectDir): Promise<StackDetection>`

- [ ] **Step 1: Write the failing tests**

`test/project/stack.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { detectStack } from '../../src/project/stack.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

async function project(files: Record<string, string>): Promise<string> {
  const dir = await tempDir('secagent-stack-');
  await writeFiles(dir, files);
  return dir;
}

describe('detectStack', () => {
  it('detects an Angular + NestJS monorepo behind nginx', async () => {
    const dir = await project({
      'web/angular.json': '{}',
      'api/nest-cli.json': '{}',
      'api/package.json': JSON.stringify({ dependencies: { '@nestjs/core': '1', express: '1' } }),
      'deploy/nginx.conf': '',
    });
    const r = await detectStack(dir);
    expect(r.stack).toEqual({ frontend: 'angular', backend: 'nestjs', proxy: 'nginx' });
    expect(r.markers.some((m) => m.includes('angular.json'))).toBe(true);
  });

  it('detects Vue only with a Vite or Vue config present', async () => {
    expect((await detectStack(await project({ 'package.json': JSON.stringify({ dependencies: { vue: '3' } }), 'vite.config.ts': '' }))).stack).toEqual({ frontend: 'vue' });
    expect((await detectStack(await project({ 'package.json': JSON.stringify({ dependencies: { vue: '3' } }) }))).stack).toEqual({});
  });

  it('detects plain Express but not Express under Nest', async () => {
    expect((await detectStack(await project({ 'package.json': JSON.stringify({ dependencies: { express: '4' } }) }))).stack).toEqual({ backend: 'express' });
  });

  it('detects Next.js on Vercel', async () => {
    expect((await detectStack(await project({ 'next.config.mjs': '', 'vercel.json': '{}' }))).stack).toEqual({ frontend: 'nextjs', hosting: 'vercel' });
  });

  it('detects nginx configs in an nginx/ folder and containers', async () => {
    expect((await detectStack(await project({ 'nginx/site.conf': '', Dockerfile: 'FROM node' }))).stack).toEqual({ proxy: 'nginx', hosting: 'container' });
  });

  it('ignores node_modules and hidden folders', async () => {
    expect((await detectStack(await project({ 'node_modules/angular.json': '{}', '.cache/nest-cli.json': '{}' }))).stack).toEqual({});
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/project/stack.test.ts`
Expected: FAIL, because `../../src/project/stack.js` can't be resolved.

- [ ] **Step 3: Implement `src/project/stack.ts`**

```ts
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import type { Stack } from './schema.js';

export interface StackDetection {
  stack: Stack;
  /** Human-readable reasons, e.g. "web/angular.json → frontend: angular". */
  markers: string[];
}

const SKIP = new Set(['node_modules', 'dist', 'build', 'coverage']);

async function listDir(dir: string): Promise<string[]> {
  try {
    return await readdir(dir);
  } catch {
    return [];
  }
}

async function readDeps(dir: string): Promise<Set<string>> {
  try {
    const pkg = JSON.parse(await readFile(path.join(dir, 'package.json'), 'utf8')) as {
      dependencies?: Record<string, string>;
      devDependencies?: Record<string, string>;
    };
    return new Set([...Object.keys(pkg.dependencies ?? {}), ...Object.keys(pkg.devDependencies ?? {})]);
  } catch {
    return new Set();
  }
}

/** Looks at the project root and its immediate subdirectories. The result only picks fix hints; checks never depend on it. */
export async function detectStack(projectDir: string): Promise<StackDetection> {
  const stack: Stack = {};
  const markers: string[] = [];
  const dirs = [projectDir];
  for (const entry of await listDir(projectDir)) {
    if (SKIP.has(entry) || entry.startsWith('.')) continue;
    const full = path.join(projectDir, entry);
    if ((await listDir(full)).length > 0) dirs.push(full);
  }

  for (const dir of dirs) {
    const entries = await listDir(dir);
    const has = (name: string) => entries.includes(name);
    const hasPrefix = (prefix: string) => entries.some((e) => e.startsWith(prefix));
    const deps = await readDeps(dir);
    const rel = path.relative(projectDir, dir) || '.';
    const mark = (field: keyof Stack, value: string, marker: string) => {
      markers.push(`${rel}/${marker} → ${field}: ${value}`);
      stack[field] ??= value;
    };

    if (has('angular.json')) mark('frontend', 'angular', 'angular.json');
    if (hasPrefix('next.config.')) mark('frontend', 'nextjs', 'next.config.*');
    if (deps.has('vue') && (hasPrefix('vite.config.') || hasPrefix('vue.config.'))) mark('frontend', 'vue', 'vue + vite/vue config');
    if (has('nest-cli.json')) mark('backend', 'nestjs', 'nest-cli.json');
    else if (deps.has('express') && !deps.has('@nestjs/core')) mark('backend', 'express', 'package.json express');
    if (has('nginx.conf')) mark('proxy', 'nginx', 'nginx.conf');
    else if (has('nginx') && (await listDir(path.join(dir, 'nginx'))).some((f) => f.endsWith('.conf'))) {
      mark('proxy', 'nginx', 'nginx/*.conf');
    }
    if (has('vercel.json')) mark('hosting', 'vercel', 'vercel.json');
    if (has('Dockerfile')) mark('hosting', 'container', 'Dockerfile');
  }
  return { stack, markers };
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/project/stack.test.ts && npx tsc -p tsconfig.json`
Expected: 6 tests PASS; `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/project/stack.ts test/project/stack.test.ts
git commit -m "feat(project): detect frontend, backend, proxy and hosting from marker files"
```

---

### Task 4: `initProject`

**Files:**
- Create: `src/project/init.ts`
- Test: `test/project/init.test.ts`

**Interfaces:**
- Consumes: `projectStateDir` (Task 1); `validateProject`, `loadProject`, `saveProject`, `projectFile`, types (Task 2); `detectStack` (Task 3)
- Produces:
  - `interface InitOptions { name?: string; scanLabel?: string; targets?: Array<{ id; url; type: 'web'|'api'; env; allow_private? }>; hosts?: Array<{ name; address; env }> }`
  - `interface InitResult { created: boolean; config: ProjectConfig; detection: StackDetection; stateDir: string }`
  - `initProject(projectDir, opts?): Promise<InitResult>`

- [ ] **Step 1: Write the failing tests**

`test/project/init.test.ts`:
```ts
import { existsSync, readFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { initProject } from '../../src/project/init.js';
import { loadProject, saveProject } from '../../src/project/schema.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

const APP = { id: 'app', url: 'https://app.example.com', type: 'web' as const, env: 'prod' };

describe('initProject', () => {
  it('creates the state tree, gitignore, knowledge files and project.yaml', async () => {
    const dir = await tempDir();
    await writeFiles(dir, { 'angular.json': '{}' });
    const r = await initProject(dir, { scanLabel: 'office', targets: [APP] });

    expect(r.created).toBe(true);
    for (const sub of ['hosts', 'external', 'evidence', 'findings/history', 'reports', 'knowledge']) {
      expect(existsSync(path.join(dir, '.secagent', sub))).toBe(true);
    }
    const gitignore = readFileSync(path.join(dir, '.secagent', '.gitignore'), 'utf8');
    for (const ignored of ['hosts/', 'external/', 'evidence/', 'findings/', 'reports/']) expect(gitignore).toContain(ignored);
    expect(existsSync(path.join(dir, '.secagent', 'knowledge', 'notes.md'))).toBe(true);
    expect(existsSync(path.join(dir, '.secagent', 'knowledge', 'exceptions.yaml'))).toBe(true);

    const p = await loadProject(dir);
    expect(p.name).toBe(path.basename(dir));
    expect(p.stack).toEqual({ frontend: 'angular' });
    expect(p.network.scan_label).toBe('office');
    expect(p.targets.map((t) => t.id)).toEqual(['app']);
  });

  it('keeps targets and user-set stack values when re-run, and fills in newly detected ones', async () => {
    const dir = await tempDir();
    await writeFiles(dir, { 'angular.json': '{}', 'nest-cli.json': '{}' });
    await initProject(dir, { targets: [APP] });
    const p = await loadProject(dir);
    await saveProject(dir, { ...p, stack: { frontend: 'vue' } });

    const r = await initProject(dir, { targets: [] });
    expect(r.created).toBe(false);
    expect(r.config.stack).toEqual({ frontend: 'vue', backend: 'nestjs' });
    expect(r.config.targets.map((t) => t.id)).toEqual(['app']);
  });

  it('never overwrites edited knowledge files', async () => {
    const dir = await tempDir();
    await initProject(dir);
    const notes = path.join(dir, '.secagent', 'knowledge', 'notes.md');
    await writeFile(notes, '# my notes\n');
    await initProject(dir);
    expect(readFileSync(notes, 'utf8')).toBe('# my notes\n');
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/project/init.test.ts`
Expected: FAIL, because `../../src/project/init.js` can't be resolved.

- [ ] **Step 3: Implement `src/project/init.ts`**

```ts
import { access, mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { projectStateDir } from '../paths.js';
import { loadProject, projectFile, saveProject, validateProject, type ProjectConfig } from './schema.js';
import { detectStack, type StackDetection } from './stack.js';

export interface InitOptions {
  name?: string;
  scanLabel?: string;
  targets?: Array<{ id: string; url: string; type: 'web' | 'api'; env: string; allow_private?: boolean }>;
  hosts?: Array<{ name: string; address: string; env: string }>;
}

export interface InitResult {
  created: boolean;
  config: ProjectConfig;
  detection: StackDetection;
  stateDir: string;
}

const STATE_SUBDIRS = ['hosts', 'external', 'evidence', 'findings/history', 'reports', 'knowledge'];

const GITIGNORE = `# Sensitive, machine-specific scan state. Only project.yaml and knowledge/ are committed.
hosts/
external/
evidence/
findings/
reports/
`;

const NOTES = `# Project security notes

Facts learned about this project. Every line cites an evidence ID.
`;

const EXCEPTIONS = `# Accepted risks. Each entry: finding_id, owner, reason, expires (YYYY-MM-DD).
exceptions: []
`;

async function exists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

async function writeIfMissing(file: string, content: string): Promise<void> {
  if (!(await exists(file))) await writeFile(file, content, 'utf8');
}

export async function initProject(projectDir: string, opts: InitOptions = {}): Promise<InitResult> {
  const stateDir = projectStateDir(projectDir);
  for (const sub of STATE_SUBDIRS) await mkdir(path.join(stateDir, sub), { recursive: true });
  await writeIfMissing(path.join(stateDir, '.gitignore'), GITIGNORE);
  await writeIfMissing(path.join(stateDir, 'knowledge', 'notes.md'), NOTES);
  await writeIfMissing(path.join(stateDir, 'knowledge', 'exceptions.yaml'), EXCEPTIONS);

  const detection = await detectStack(projectDir);
  const created = !(await exists(projectFile(projectDir)));
  let config: ProjectConfig;
  if (created) {
    config = validateProject({
      version: 1,
      name: opts.name ?? path.basename(path.resolve(projectDir)),
      stack: detection.stack,
      network: { scan_label: opts.scanLabel ?? 'unlabelled' },
      targets: opts.targets ?? [],
      hosts: opts.hosts ?? [],
    });
  } else {
    // Re-running init only fills in stack values the user has not set. Targets and hosts are never touched.
    const existing = await loadProject(projectDir);
    config = validateProject({ ...existing, stack: { ...detection.stack, ...existing.stack } });
  }
  await saveProject(projectDir, config);
  return { created, config, detection, stateDir };
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/project/init.test.ts && npx tsc -p tsconfig.json`
Expected: 3 tests PASS; `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/project/init.ts test/project/init.test.ts
git commit -m "feat(project): add initProject creating the .secagent state folder"
```

---

### Task 5: Network errors, address helpers and the scope guard

**Files:**
- Create: `src/net/errors.ts`, `src/net/ip.ts`, `src/project/scope.ts`
- Test: `test/net/ip.test.ts`, `test/project/scope.test.ts`

**Interfaces:**
- Consumes: `validateProject`, types `ProjectConfig`, `Target`, `Host` (Task 2)
- Produces:
  - `class NetError extends Error { code: string }`
  - `toNetError(e: unknown, fallbackCode?): NetError`
  - `stripBrackets(host): string`, `isPrivateAddress(ip): boolean`, `resolveAddresses(hostname, family: 4|6): Promise<string[]>` (throws `NetError`)
  - `class ScopeError extends Error`
  - `class Scope`:
    - `constructor(project: ProjectConfig)`
    - `target(id): Target`, `host(name): Host`
    - `assertHostnameAllowed(hostname): Promise<string[]>`
    - `assertUrlAllowed(url): Promise<string[]>`

- [ ] **Step 1: Write the failing tests**

`test/net/ip.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { NetError } from '../../src/net/errors.js';
import { isPrivateAddress, resolveAddresses, stripBrackets } from '../../src/net/ip.js';

describe('isPrivateAddress', () => {
  it.each([
    ['10.1.2.3', true],
    ['172.16.0.1', true],
    ['172.31.250.10', true],
    ['192.168.1.1', true],
    ['127.0.0.1', true],
    ['169.254.169.254', true],
    ['100.64.0.1', true],
    ['::1', true],
    ['fd00::1', true],
    ['fe80::1', true],
    ['::ffff:10.0.0.1', true],
    ['203.0.113.10', false],
    ['8.8.8.8', false],
    ['2001:db8::1', false],
    ['not-an-ip', false],
  ])('%s → %s', (ip, expected) => {
    expect(isPrivateAddress(ip)).toBe(expected);
  });
});

describe('resolveAddresses', () => {
  it('returns IP literals unchanged', async () => {
    expect(await resolveAddresses('203.0.113.10', 4)).toEqual(['203.0.113.10']);
    expect(await resolveAddresses('[::1]', 6)).toEqual(['::1']);
  });
  it('resolves localhost', async () => {
    expect(await resolveAddresses('localhost', 4)).toContain('127.0.0.1');
  });
  it('wraps DNS failures in NetError', async () => {
    await expect(resolveAddresses('does-not-exist.invalid', 4)).rejects.toBeInstanceOf(NetError);
  });
  it('strips IPv6 brackets', () => {
    expect(stripBrackets('[::1]')).toBe('::1');
  });
});
```

`test/project/scope.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { validateProject } from '../../src/project/schema.js';
import { Scope, ScopeError } from '../../src/project/scope.js';

function scopeFor(targets: unknown[], hosts: unknown[] = []): Scope {
  return new Scope(validateProject({ version: 1, name: 't', targets, hosts }));
}

describe('Scope', () => {
  it('rejects hostnames that are not listed', async () => {
    const scope = scopeFor([{ id: 'app', url: 'https://203.0.113.10', type: 'web', env: 'prod' }]);
    await expect(scope.assertHostnameAllowed('198.51.100.7')).rejects.toThrow(/not in project.yaml/);
  });

  it('allows listed target hostnames and host addresses', async () => {
    const scope = scopeFor(
      [{ id: 'app', url: 'https://203.0.113.10:8443', type: 'web', env: 'prod' }],
      [{ name: 'web-1', address: '203.0.113.11', env: 'prod' }],
    );
    expect(await scope.assertHostnameAllowed('203.0.113.10')).toEqual(['203.0.113.10']);
    expect(await scope.assertUrlAllowed('http://203.0.113.10/')).toEqual(['203.0.113.10']);
    expect(await scope.assertHostnameAllowed('203.0.113.11')).toEqual(['203.0.113.11']);
  });

  it('treats a private IP literal as explicitly listed', async () => {
    const scope = scopeFor([{ id: 'lab', url: 'https://172.31.250.10', type: 'web', env: 'lab' }]);
    expect(await scope.assertHostnameAllowed('172.31.250.10')).toEqual(['172.31.250.10']);
  });

  it('blocks a hostname that resolves to a private address unless allow_private is set', async () => {
    const blocked = scopeFor([{ id: 'local', url: 'http://localhost:3000', type: 'web', env: 'dev' }]);
    await expect(blocked.assertHostnameAllowed('LOCALHOST')).rejects.toThrow(/allow_private/);
    const allowed = scopeFor([{ id: 'local', url: 'http://localhost:3000', type: 'web', env: 'dev', allow_private: true }]);
    expect(await allowed.assertHostnameAllowed('localhost')).toContain('127.0.0.1');
  });

  it('rejects non-http URLs', async () => {
    const scope = scopeFor([{ id: 'app', url: 'https://203.0.113.10', type: 'web', env: 'prod' }]);
    await expect(scope.assertUrlAllowed('ftp://203.0.113.10/')).rejects.toBeInstanceOf(ScopeError);
  });

  it('looks up targets and hosts by id with a helpful error', () => {
    const scope = scopeFor([{ id: 'app', url: 'https://203.0.113.10', type: 'web', env: 'prod' }]);
    expect(scope.target('app').url).toBe('https://203.0.113.10');
    expect(() => scope.target('nope')).toThrow(/Targets in project.yaml: app/);
    expect(() => scope.host('nope')).toThrow(ScopeError);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/net/ip.test.ts test/project/scope.test.ts`
Expected: FAIL, because the modules can't be resolved.

- [ ] **Step 3: Implement `src/net/errors.ts`, `src/net/ip.ts`, `src/project/scope.ts`**

`src/net/errors.ts`:
```ts
/** A network-level failure (DNS, connect, timeout, TLS). The check runner turns these into "unverifiable". */
export class NetError extends Error {
  constructor(
    public readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = 'NetError';
  }
}

export function toNetError(e: unknown, fallbackCode = 'NET_ERROR'): NetError {
  if (e instanceof NetError) return e;
  const err = e as NodeJS.ErrnoException | undefined;
  return new NetError(err?.code ?? fallbackCode, err?.message ?? String(e));
}
```

`src/net/ip.ts`:
```ts
import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { toNetError } from './errors.js';

const PRIVATE_V4 = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
] as const) {
  PRIVATE_V4.addSubnet(net, prefix, 'ipv4');
}

const PRIVATE_V6 = new BlockList();
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
] as const) {
  PRIVATE_V6.addSubnet(net, prefix, 'ipv6');
}

export function stripBrackets(host: string): string {
  return host.replace(/^\[|\]$/g, '');
}

/** True for loopback, RFC 1918, CGNAT, link-local, unique-local and unspecified addresses. */
export function isPrivateAddress(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return PRIVATE_V4.check(ip, 'ipv4');
  if (version === 6) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip)?.[1];
    if (mapped) return PRIVATE_V4.check(mapped, 'ipv4');
    return PRIVATE_V6.check(ip, 'ipv6');
  }
  return false;
}

/** Resolves a hostname for the given family; IP literals are returned as-is. DNS failures become NetError. */
export async function resolveAddresses(hostname: string, family: 4 | 6): Promise<string[]> {
  const bare = stripBrackets(hostname);
  if (isIP(bare)) return [bare];
  try {
    const results = await lookup(bare, { family, all: true });
    return results.map((r) => r.address);
  } catch (e) {
    throw toNetError(e, 'DNS_FAILED');
  }
}
```

`src/project/scope.ts`:
```ts
import { isIP } from 'node:net';
import { isPrivateAddress, resolveAddresses, stripBrackets } from '../net/ip.js';
import type { Host, ProjectConfig, Target } from './schema.js';

export class ScopeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'ScopeError';
  }
}

interface ScopeEntry {
  hostname: string;
  allowPrivate: boolean;
}

function normalise(hostname: string): string {
  return stripBrackets(hostname).toLowerCase();
}

/**
 * The allowlist every probe goes through. A hostname is in scope when it is a listed target's hostname
 * or a listed host's address. Private addresses are only reachable when listed as an IP literal or when
 * the entry sets allow_private.
 */
export class Scope {
  private readonly entries: ScopeEntry[];
  private readonly checked = new Map<string, Promise<string[]>>();

  constructor(private readonly project: ProjectConfig) {
    this.entries = [
      ...project.targets.map((t) => ({ hostname: normalise(new URL(t.url).hostname), allowPrivate: t.allow_private })),
      ...project.hosts.map((h) => ({ hostname: normalise(h.address), allowPrivate: h.allow_private })),
    ];
  }

  target(id: string): Target {
    const target = this.project.targets.find((t) => t.id === id);
    if (!target) {
      const known = this.project.targets.map((t) => t.id).join(', ') || '(none)';
      throw new ScopeError(`Unknown target "${id}". Targets in project.yaml: ${known}`);
    }
    return target;
  }

  host(name: string): Host {
    const host = this.project.hosts.find((h) => h.name === name);
    if (!host) {
      const known = this.project.hosts.map((h) => h.name).join(', ') || '(none)';
      throw new ScopeError(`Unknown host "${name}". Hosts in project.yaml: ${known}`);
    }
    return host;
  }

  async assertHostnameAllowed(hostname: string): Promise<string[]> {
    const h = normalise(hostname);
    const matches = this.entries.filter((e) => e.hostname === h);
    if (matches.length === 0) {
      throw new ScopeError(
        `"${hostname}" is not in project.yaml (targets/hosts). secagent only probes listed targets; add it there if it belongs to this project.`,
      );
    }
    let pending = this.checked.get(h);
    if (!pending) {
      pending = this.resolveChecked(h, matches.some((m) => m.allowPrivate));
      this.checked.set(h, pending);
    }
    return pending;
  }

  async assertUrlAllowed(url: string): Promise<string[]> {
    const u = new URL(url);
    if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new ScopeError(`Only http(s) URLs can be probed: ${url}`);
    return this.assertHostnameAllowed(u.hostname);
  }

  private async resolveChecked(hostname: string, allowPrivate: boolean): Promise<string[]> {
    const addresses = await resolveAddresses(hostname, this.project.network.ip_family);
    if (!allowPrivate && !isIP(hostname)) {
      const priv = addresses.filter(isPrivateAddress);
      if (priv.length > 0) {
        throw new ScopeError(
          `"${hostname}" resolves to private address(es) ${priv.join(', ')}. Set allow_private: true on its project.yaml entry to probe it.`,
        );
      }
    }
    return addresses;
  }
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/net/ip.test.ts test/project/scope.test.ts && npx tsc -p tsconfig.json`
Expected: all tests PASS (15 `isPrivateAddress` cases, 4 resolve tests, 6 scope tests); `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/net/errors.ts src/net/ip.ts src/project/scope.ts test/net/ip.test.ts test/project/scope.test.ts
git commit -m "feat(scope): enforce project.yaml allowlist and private-address guard"
```

---

### Task 6: HTTP probe and local test servers

**Files:**
- Create: `test/fixtures/tls/key.pem`, `test/fixtures/tls/cert.pem` (generated), `test/helpers/servers.ts`, `src/net/http.ts`
- Test: `test/net/http.test.ts`

**Interfaces:**
- Consumes: `NetError`, `toNetError` (Task 5); `stripBrackets` (Task 5)
- Produces:
  - `interface CookieObservation { name: string; attributes: string[]; redacted: string }`
  - `interface HttpObservation { url; status; headers: Record<string,string>; setCookies: CookieObservation[]; location?; headerBytes; bodySnippet; bodyBytes; remoteAddress? }`
  - `interface HttpOptions { family: 4|6; timeoutMs?; connectTimeoutMs?; method?: 'GET'|'HEAD'; headers?; maxBodyBytes? }`
  - `USER_AGENT`, `parseSetCookie(raw)`, `countHeaderBytes(statusLine, rawHeaders)`, `httpRequest(url, opts): Promise<HttpObservation>`
  - test helpers `startHttp(handler)`, `startHttps(handler, tlsOpts?)`, `startTls(tlsOpts?)` → `Running { port; url; close() }`, plus `TEST_KEY`, `TEST_CERT`

- [ ] **Step 1: Generate the test certificate (valid ten years; SAN localhost + 127.0.0.1)**

Run:
```bash
mkdir -p test/fixtures/tls
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
  -keyout test/fixtures/tls/key.pem -out test/fixtures/tls/cert.pem
```
Expected: both files exist. This is a test-only key with no other use.

- [ ] **Step 2: Write the server helper and the failing tests**

`test/helpers/servers.ts`:
```ts
import { readFileSync } from 'node:fs';
import http from 'node:http';
import https from 'node:https';
import type { AddressInfo } from 'node:net';
import path from 'node:path';
import tls from 'node:tls';

const FIXTURES = path.join(import.meta.dirname, '..', 'fixtures', 'tls');
export const TEST_KEY = readFileSync(path.join(FIXTURES, 'key.pem'));
export const TEST_CERT = readFileSync(path.join(FIXTURES, 'cert.pem'));

export interface Running {
  port: number;
  url: string;
  close(): Promise<void>;
}

type Handler = (req: http.IncomingMessage, res: http.ServerResponse) => void;

function listen(server: http.Server | https.Server | tls.Server, scheme: string): Promise<Running> {
  return new Promise((resolve) => {
    server.listen(0, '127.0.0.1', () => {
      const { port } = server.address() as AddressInfo;
      resolve({
        port,
        url: `${scheme}://127.0.0.1:${port}`,
        close: () =>
          new Promise<void>((done) => {
            if ('closeAllConnections' in server) server.closeAllConnections();
            server.close(() => done());
          }),
      });
    });
  });
}

export function startHttp(handler: Handler): Promise<Running> {
  return listen(http.createServer(handler), 'http');
}

export function startHttps(handler: Handler, tlsOpts: tls.TlsOptions = {}): Promise<Running> {
  return listen(https.createServer({ key: TEST_KEY, cert: TEST_CERT, ...tlsOpts }, handler), 'https');
}

/** A bare TLS server that completes the handshake and closes. */
export function startTls(tlsOpts: tls.TlsOptions = {}): Promise<Running> {
  const server = tls.createServer({ key: TEST_KEY, cert: TEST_CERT, ...tlsOpts }, (socket) => socket.end());
  server.on('tlsClientError', () => {});
  return listen(server, 'tls');
}
```

`test/net/http.test.ts`:
```ts
import { afterEach, describe, expect, it } from 'vitest';
import { NetError } from '../../src/net/errors.js';
import { countHeaderBytes, httpRequest, parseSetCookie } from '../../src/net/http.js';
import { startHttp, startHttps, type Running } from '../helpers/servers.js';

const running: Running[] = [];
afterEach(async () => {
  await Promise.all(running.splice(0).map((s) => s.close()));
});
async function track(p: Promise<Running>): Promise<Running> {
  const s = await p;
  running.push(s);
  return s;
}

describe('parseSetCookie', () => {
  it('keeps the name, lowercases attributes and redacts the value', () => {
    expect(parseSetCookie('sid=abc123; Path=/; Secure; HttpOnly; SameSite=Lax')).toEqual({
      name: 'sid',
      attributes: ['path=/', 'secure', 'httponly', 'samesite=lax'],
      redacted: 'sid=<redacted>; Path=/; Secure; HttpOnly; SameSite=Lax',
    });
  });
});

describe('countHeaderBytes', () => {
  it('counts the status line, each header line and the blank line', () => {
    expect(countHeaderBytes('HTTP/1.1 200 OK', ['A', 'b'])).toBe(17 + 6 + 2);
  });
});

describe('httpRequest', () => {
  it('captures status, headers and redacted cookies without following redirects', async () => {
    const s = await track(
      startHttp((_req, res) => {
        res.setHeader('x-test', 'yes');
        res.setHeader('set-cookie', ['sid=topsecret; Secure', 'theme=dark']);
        res.writeHead(301, { location: 'https://example.com/' });
        res.end('moved');
      }),
    );
    const obs = await httpRequest(`${s.url}/`, { family: 4 });
    expect(obs.status).toBe(301);
    expect(obs.location).toBe('https://example.com/');
    expect(obs.headers['x-test']).toBe('yes');
    expect(obs.setCookies.map((c) => c.name)).toEqual(['sid', 'theme']);
    expect(JSON.stringify(obs)).not.toContain('topsecret');
    expect(obs.headerBytes).toBeGreaterThan(50);
    expect(obs.bodySnippet).toBe('moved');
  });

  it('accepts a self-signed HTTPS server (the tls check judges certificates)', async () => {
    const s = await track(startHttps((_req, res) => res.end('ok')));
    expect((await httpRequest(`${s.url}/`, { family: 4 })).status).toBe(200);
  });

  it('rejects with TIMEOUT when the server never answers', async () => {
    const s = await track(startHttp(() => {}));
    await expect(httpRequest(`${s.url}/`, { family: 4, timeoutMs: 300 })).rejects.toMatchObject({ code: 'TIMEOUT' });
  });

  it('rejects with ECONNREFUSED on a closed port', async () => {
    const s = await startHttp((_req, res) => res.end());
    await s.close();
    const err = await httpRequest(`${s.url}/`, { family: 4 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetError);
    expect((err as NetError).code).toBe('ECONNREFUSED');
  });

  it('caps how much body it reads', async () => {
    const s = await track(startHttp((_req, res) => res.end('x'.repeat(1_000_000))));
    const obs = await httpRequest(`${s.url}/`, { family: 4, maxBodyBytes: 1024 });
    expect(obs.bodyBytes).toBeGreaterThanOrEqual(1024);
    expect(obs.bodySnippet.length).toBeLessThanOrEqual(4096);
  });
});
```

- [ ] **Step 3: Run the tests to verify they fail**

Run: `npx vitest run test/net/http.test.ts`
Expected: FAIL, because `../../src/net/http.js` can't be resolved.

- [ ] **Step 4: Implement `src/net/http.ts`**

```ts
import http from 'node:http';
import https from 'node:https';
import { NetError, toNetError } from './errors.js';
import { stripBrackets } from './ip.js';

export interface CookieObservation {
  name: string;
  /** Lowercased attributes, e.g. ["secure", "httponly", "samesite=lax", "path=/"]. */
  attributes: string[];
  /** The Set-Cookie line with the value replaced by <redacted>. */
  redacted: string;
}

export interface HttpObservation {
  url: string;
  status: number;
  /** Lowercased header names; repeated headers joined with ", ". Set-Cookie is only in setCookies. */
  headers: Record<string, string>;
  setCookies: CookieObservation[];
  location?: string;
  /** Approximate wire size of the status line plus all response headers. */
  headerBytes: number;
  bodySnippet: string;
  bodyBytes: number;
  remoteAddress?: string;
}

export interface HttpOptions {
  family: 4 | 6;
  timeoutMs?: number;
  connectTimeoutMs?: number;
  method?: 'GET' | 'HEAD';
  headers?: Record<string, string>;
  maxBodyBytes?: number;
}

export const USER_AGENT = 'secagent/0.1 (+security self-assessment; authorised targets only)';
const SNIPPET_CHARS = 4096;

export function parseSetCookie(raw: string): CookieObservation {
  const [pair = '', ...rest] = raw.split(';').map((s) => s.trim());
  const attrs = rest.filter(Boolean);
  const eq = pair.indexOf('=');
  const name = eq === -1 ? pair : pair.slice(0, eq);
  return {
    name,
    attributes: attrs.map((a) => a.toLowerCase()),
    redacted: [`${name}=<redacted>`, ...attrs].join('; '),
  };
}

export function countHeaderBytes(statusLine: string, rawHeaders: readonly string[]): number {
  let total = Buffer.byteLength(`${statusLine}\r\n`);
  for (let i = 0; i + 1 < rawHeaders.length; i += 2) {
    total += Buffer.byteLength(`${rawHeaders[i]}: ${rawHeaders[i + 1]}\r\n`);
  }
  return total + 2;
}

/** One request, no redirect following, certificate errors ignored (the tls check judges certificates). */
export function httpRequest(url: string, opts: HttpOptions): Promise<HttpObservation> {
  const u = new URL(url);
  const isHttps = u.protocol === 'https:';
  const lib = isHttps ? https : http;
  const timeoutMs = opts.timeoutMs ?? 10_000;
  const connectTimeoutMs = opts.connectTimeoutMs ?? 5_000;
  const maxBody = opts.maxBodyBytes ?? 256 * 1024;

  return new Promise<HttpObservation>((resolve, reject) => {
    const req = lib.request({
      protocol: u.protocol,
      hostname: stripBrackets(u.hostname),
      port: u.port || undefined,
      path: `${u.pathname}${u.search}`,
      method: opts.method ?? 'GET',
      family: opts.family,
      headers: { 'user-agent': USER_AGENT, accept: '*/*', ...opts.headers },
      rejectUnauthorized: false,
      agent: false,
    });
    const totalTimer = setTimeout(
      () => req.destroy(new NetError('TIMEOUT', `No complete response from ${url} within ${timeoutMs}ms`)),
      timeoutMs,
    );
    let settled = false;
    const settle = (fn: () => void) => {
      if (settled) return;
      settled = true;
      clearTimeout(totalTimer);
      fn();
    };

    req.on('socket', (socket) => {
      const connectTimer = setTimeout(
        () => req.destroy(new NetError('CONNECT_TIMEOUT', `Could not connect to ${u.host} within ${connectTimeoutMs}ms`)),
        connectTimeoutMs,
      );
      socket.once(isHttps ? 'secureConnect' : 'connect', () => clearTimeout(connectTimer));
      socket.once('close', () => clearTimeout(connectTimer));
    });

    req.on('error', (e) => settle(() => reject(toNetError(e))));

    req.on('response', (res) => {
      const remoteAddress = res.socket?.remoteAddress;
      const chunks: Buffer[] = [];
      let bodyBytes = 0;
      res.on('data', (chunk: Buffer) => {
        if (bodyBytes < maxBody) chunks.push(chunk);
        bodyBytes += chunk.length;
        if (bodyBytes >= maxBody) res.destroy();
      });
      const finish = () =>
        settle(() => {
          const headers: Record<string, string> = {};
          for (const [key, value] of Object.entries(res.headers)) {
            if (key === 'set-cookie' || value === undefined) continue;
            headers[key] = Array.isArray(value) ? value.join(', ') : value;
          }
          resolve({
            url,
            status: res.statusCode ?? 0,
            headers,
            setCookies: (res.headers['set-cookie'] ?? []).map(parseSetCookie),
            ...(res.headers.location ? { location: res.headers.location } : {}),
            headerBytes: countHeaderBytes(`HTTP/${res.httpVersion} ${res.statusCode ?? 0} ${res.statusMessage ?? ''}`, res.rawHeaders),
            bodySnippet: Buffer.concat(chunks).toString('utf8').slice(0, SNIPPET_CHARS),
            bodyBytes,
            ...(remoteAddress ? { remoteAddress } : {}),
          });
        });
      res.on('end', finish);
      res.on('close', finish);
      // A body cut short still carries the status and headers the checks need.
      res.on('error', finish);
    });

    req.end();
  });
}
```

- [ ] **Step 5: Run tests and typecheck**

Run: `npx vitest run test/net/http.test.ts && npx tsc -p tsconfig.json`
Expected: 7 tests PASS; `tsc` exits 0.

- [ ] **Step 6: Commit**

```bash
git add test/fixtures/tls/key.pem test/fixtures/tls/cert.pem test/helpers/servers.ts src/net/http.ts test/net/http.test.ts
git commit -m "feat(net): add HTTP probe with cookie redaction and header byte count"
```

---

### Task 7: TLS and TCP probes

**Files:**
- Create: `src/net/tls.ts`, `src/net/tcp.ts`
- Test: `test/net/tls.test.ts`, `test/net/tcp.test.ts`

**Interfaces:**
- Consumes: `NetError`, `toNetError`, `stripBrackets` (Task 5); `startTls`, `startHttp` (Task 6)
- Produces:
  - `LEGACY_CIPHERS = 'DEFAULT@SECLEVEL=0'`
  - `NON_AEAD_TLS12_CIPHERS = 'DEFAULT:!AESGCM:!CHACHA20:!AESCCM:@SECLEVEL=0'`
  - `interface CertInfo { subject; issuer; valid_from; valid_to; subjectaltname?; days_remaining; hostname_ok; hostname_error? }`
  - `interface TlsObservation { host; port; protocol: string|null; cipher: string|null; authorized: boolean; authorization_error?; cert?: CertInfo }`
  - `interface TlsOptions { family: 4|6; timeoutMs?; servername?; minVersion?: SecureVersion; maxVersion?: SecureVersion; ciphers?; now? }`
  - `isHandshakeRejection(code): boolean`, `tlsHandshake(host, port, opts): Promise<TlsObservation>` (throws `NetError`)
  - `type PortState = 'open'|'closed'|'timeout'|'unreachable'`, `tcpProbe(host, port, { family, timeoutMs? }): Promise<PortState>` (never throws)

Verified on Node 24 / OpenSSL 3.5 during planning:
- A client limited to TLS 1.0 completes against a legacy server.
- A modern server refuses it with `ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION`.
- The non-AEAD probe is refused by a strict server with an `ERR_SSL_*` code.
- `!AEAD` does **not** work as an exclusion in this OpenSSL. Use the explicit `!AESGCM:!CHACHA20:!AESCCM`.

- [ ] **Step 1: Write the failing tests**

`test/net/tls.test.ts`:
```ts
import { afterEach, describe, expect, it } from 'vitest';
import { NetError } from '../../src/net/errors.js';
import { isHandshakeRejection, LEGACY_CIPHERS, NON_AEAD_TLS12_CIPHERS, tlsHandshake } from '../../src/net/tls.js';
import { startTls, type Running } from '../helpers/servers.js';

const STRICT_CIPHERS =
  'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
const TLS10 = { minVersion: 'TLSv1', maxVersion: 'TLSv1', ciphers: LEGACY_CIPHERS } as const;

const running: Running[] = [];
afterEach(async () => {
  await Promise.all(running.splice(0).map((s) => s.close()));
});
async function track(p: Promise<Running>): Promise<Running> {
  const s = await p;
  running.push(s);
  return s;
}

describe('tlsHandshake', () => {
  it('completes a TLS 1.0 handshake with a legacy server', async () => {
    const s = await track(startTls({ minVersion: 'TLSv1', ciphers: LEGACY_CIPHERS }));
    const obs = await tlsHandshake('127.0.0.1', s.port, { family: 4, ...TLS10 });
    expect(obs.protocol).toBe('TLSv1');
  });

  it('surfaces a modern server refusing TLS 1.0 as a handshake rejection', async () => {
    const s = await track(startTls({ minVersion: 'TLSv1.2' }));
    const err = await tlsHandshake('127.0.0.1', s.port, { family: 4, ...TLS10 }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetError);
    expect(isHandshakeRejection((err as NetError).code)).toBe(true);
  });

  it('reads protocol, trust and hostname match from a default handshake', async () => {
    const s = await track(startTls({ minVersion: 'TLSv1.2' }));
    const obs = await tlsHandshake('127.0.0.1', s.port, { family: 4 });
    expect(obs.protocol).toBe('TLSv1.3');
    expect(obs.authorized).toBe(false);
    expect(obs.authorization_error).toBe('DEPTH_ZERO_SELF_SIGNED_CERT');
    expect(obs.cert?.hostname_ok).toBe(true);
    expect(obs.cert?.days_remaining).toBeGreaterThan(300);
  });

  it('flags a hostname mismatch when SNI names another host', async () => {
    const s = await track(startTls({ minVersion: 'TLSv1.2' }));
    const obs = await tlsHandshake('127.0.0.1', s.port, { family: 4, servername: 'example.com' });
    expect(obs.cert?.hostname_ok).toBe(false);
  });

  it('is refused when offering only non-AEAD TLS 1.2 ciphers to a strict server', async () => {
    const s = await track(startTls({ minVersion: 'TLSv1.2', ciphers: STRICT_CIPHERS }));
    const err = await tlsHandshake('127.0.0.1', s.port, {
      family: 4,
      minVersion: 'TLSv1.2',
      maxVersion: 'TLSv1.2',
      ciphers: NON_AEAD_TLS12_CIPHERS,
    }).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(NetError);
    expect(isHandshakeRejection((err as NetError).code)).toBe(true);
  });
});

describe('isHandshakeRejection', () => {
  it.each([
    ['ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION', true],
    ['ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE', true],
    ['ERR_SSL_UNSUPPORTED_PROTOCOL', true],
    ['ECONNRESET', true],
    ['ERR_SSL_NO_PROTOCOLS_AVAILABLE', false],
    ['TIMEOUT', false],
    ['ECONNREFUSED', false],
    ['ENOTFOUND', false],
  ])('%s → %s', (code, expected) => {
    expect(isHandshakeRejection(code)).toBe(expected);
  });
});
```

`test/net/tcp.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { tcpProbe } from '../../src/net/tcp.js';
import { startHttp } from '../helpers/servers.js';

describe('tcpProbe', () => {
  it('reports open for a listening port and closed once it stops', async () => {
    const s = await startHttp((_req, res) => res.end());
    expect(await tcpProbe('127.0.0.1', s.port, { family: 4 })).toBe('open');
    await s.close();
    expect(await tcpProbe('127.0.0.1', s.port, { family: 4 })).toBe('closed');
  });

  it('never throws for a silent address', async () => {
    const state = await tcpProbe('10.255.255.1', 9, { family: 4, timeoutMs: 300 });
    expect(['timeout', 'unreachable']).toContain(state);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/net/tls.test.ts test/net/tcp.test.ts`
Expected: FAIL, because the modules can't be resolved.

- [ ] **Step 3: Implement `src/net/tls.ts` and `src/net/tcp.ts`**

`src/net/tls.ts`:
```ts
import { isIP } from 'node:net';
import tls, { type PeerCertificate, type SecureVersion } from 'node:tls';
import { NetError, toNetError } from './errors.js';
import { stripBrackets } from './ip.js';

/** Lets the client offer TLS 1.0/1.1 suites that OpenSSL 3 disables at the default security level. */
export const LEGACY_CIPHERS = 'DEFAULT@SECLEVEL=0';
/** TLS 1.2 suites without AEAD (CBC etc.). "!AEAD" is not a working exclusion in OpenSSL 3.5. */
export const NON_AEAD_TLS12_CIPHERS = 'DEFAULT:!AESGCM:!CHACHA20:!AESCCM:@SECLEVEL=0';

export interface CertInfo {
  subject: string;
  issuer: string;
  valid_from: string;
  valid_to: string;
  subjectaltname?: string;
  days_remaining: number;
  hostname_ok: boolean;
  hostname_error?: string;
}

export interface TlsObservation {
  host: string;
  port: number;
  protocol: string | null;
  cipher: string | null;
  authorized: boolean;
  authorization_error?: string;
  cert?: CertInfo;
}

export interface TlsOptions {
  family: 4 | 6;
  timeoutMs?: number;
  servername?: string;
  minVersion?: SecureVersion;
  maxVersion?: SecureVersion;
  ciphers?: string;
  now?: Date;
}

/** Our own client could not offer what was asked: the server's policy was never observed. */
const CLIENT_SIDE = new Set(['ERR_SSL_NO_PROTOCOLS_AVAILABLE', 'ERR_SSL_NO_CIPHERS_AVAILABLE', 'ERR_SSL_NO_CIPHER_MATCH']);
/** Network failures: nothing about TLS was observed. */
const NETWORK = new Set(['TIMEOUT', 'CONNECT_TIMEOUT', 'ECONNREFUSED', 'ENOTFOUND', 'EAI_AGAIN', 'EHOSTUNREACH', 'ENETUNREACH', 'ETIMEDOUT', 'DNS_FAILED']);

/** True when an error code means the server refused the offered protocol or ciphers. */
export function isHandshakeRejection(code: string): boolean {
  if (CLIENT_SIDE.has(code) || NETWORK.has(code)) return false;
  return code.startsWith('ERR_SSL_') || code === 'ECONNRESET' || code === 'EPIPE';
}

function formatName(name: unknown): string {
  if (!name || typeof name !== 'object') return '';
  return Object.entries(name as Record<string, unknown>)
    .map(([k, v]) => `${k}=${String(v)}`)
    .join(', ');
}

function certInfo(peer: PeerCertificate | undefined, identityName: string, now: Date): CertInfo | undefined {
  if (!peer || Object.keys(peer).length === 0) return undefined;
  const identityError = tls.checkServerIdentity(identityName, peer);
  return {
    subject: formatName(peer.subject),
    issuer: formatName(peer.issuer),
    valid_from: peer.valid_from,
    valid_to: peer.valid_to,
    ...(peer.subjectaltname ? { subjectaltname: peer.subjectaltname } : {}),
    days_remaining: Math.floor((Date.parse(peer.valid_to) - now.getTime()) / 86_400_000),
    hostname_ok: identityError === undefined,
    ...(identityError ? { hostname_error: identityError.message } : {}),
  };
}

export function tlsHandshake(host: string, port: number, opts: TlsOptions): Promise<TlsObservation> {
  const bare = stripBrackets(host);
  const servername = opts.servername ?? (isIP(bare) ? undefined : bare);
  const timeoutMs = opts.timeoutMs ?? 10_000;
  // `family` is passed through to net.connect; @types/node's tls.ConnectionOptions does not declare it.
  const options: tls.ConnectionOptions & { family: 4 | 6 } = {
    host: bare,
    port,
    family: opts.family,
    rejectUnauthorized: false,
    ...(servername ? { servername } : {}),
    ...(opts.minVersion ? { minVersion: opts.minVersion } : {}),
    ...(opts.maxVersion ? { maxVersion: opts.maxVersion } : {}),
    ...(opts.ciphers ? { ciphers: opts.ciphers } : {}),
  };

  return new Promise((resolve, reject) => {
    const socket = tls.connect(options);
    const timer = setTimeout(
      () => socket.destroy(new NetError('TIMEOUT', `TLS handshake with ${bare}:${port} did not finish within ${timeoutMs}ms`)),
      timeoutMs,
    );
    socket.once('secureConnect', () => {
      clearTimeout(timer);
      const authError = socket.authorizationError;
      const cert = certInfo(socket.getPeerCertificate(), servername ?? bare, opts.now ?? new Date());
      resolve({
        host: bare,
        port,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name ?? null,
        authorized: socket.authorized,
        ...(authError ? { authorization_error: String(authError) } : {}),
        ...(cert ? { cert } : {}),
      });
      socket.end();
    });
    socket.once('error', (e) => {
      clearTimeout(timer);
      reject(toNetError(e));
    });
  });
}
```

`src/net/tcp.ts`:
```ts
import net from 'node:net';
import { stripBrackets } from './ip.js';

export type PortState = 'open' | 'closed' | 'timeout' | 'unreachable';

/** TCP connect only, never sends data. "closed" = refused (host answered); "timeout" = filtered or silent. */
export function tcpProbe(host: string, port: number, opts: { family: 4 | 6; timeoutMs?: number }): Promise<PortState> {
  const timeoutMs = opts.timeoutMs ?? 5_000;
  return new Promise((resolve) => {
    const socket = net.connect({ host: stripBrackets(host), port, family: opts.family });
    let settled = false;
    const finish = (state: PortState) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      socket.destroy();
      resolve(state);
    };
    const timer = setTimeout(() => finish('timeout'), timeoutMs);
    socket.once('connect', () => finish('open'));
    socket.once('error', (e: NodeJS.ErrnoException) => finish(e.code === 'ECONNREFUSED' ? 'closed' : 'unreachable'));
  });
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/net/tls.test.ts test/net/tcp.test.ts && npx tsc -p tsconfig.json`
Expected: all tests PASS (5 handshake, 8 classification, 2 tcp); `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/net/tls.ts src/net/tcp.ts test/net/tls.test.ts test/net/tcp.test.ts
git commit -m "feat(net): add TLS handshake and TCP connect probes"
```

---

### Task 8: `ScopedNet`, evidence store and check context

**Files:**
- Create: `src/net/scoped.ts`, `src/evidence/store.ts`, `src/checks/context.ts`, `test/helpers/ctx.ts`
- Test: `test/net/scoped.test.ts`, `test/evidence/store.test.ts`, `test/checks/context.test.ts`

**Interfaces:**
- Consumes: `Scope`, `ScopeError` (Task 5); `httpRequest`, `HttpObservation`, `HttpOptions` (Task 6); `tlsHandshake`, `TlsObservation`, `TlsOptions`, `tcpProbe`, `PortState` (Task 7); `NetError` (Task 5); `projectStateDir` (Task 1); `validateProject` and types (Task 2)
- Produces:
  - `interface NetClient`:
    - `http(url, opts?: { method?; headers? }): Promise<HttpObservation>`
    - `tls(host, port, opts?: { minVersion?; maxVersion?; ciphers?; servername? }): Promise<TlsObservation>`
    - `tcp(host, port): Promise<PortState>`
  - `class ScopedNet implements NetClient`:
    - `constructor(scope: Scope, family: 4|6, timeouts?: { totalMs; connectMs })`
  - `withRetry(fn, retries?)`
  - `EVIDENCE_ID_PATTERN`
  - `type EvidenceKind = 'http'|'tls'|'tcp'|'note'`
  - `interface EvidenceRecord { id; kind; target; scan_label; captured_at; summary; data }`
  - `newEvidenceId(now)`
  - `class EvidenceStore`:
    - `constructor(projectDir, scanLabel, now?)`
    - `put(kind, target, summary, data): Promise<string>`
    - `get(id)`
  - `type CheckSubject = { kind: 'target'; target: Target } | { kind: 'host'; host: Host }`
  - `interface CheckContext { project; net: NetClient; evidence: EvidenceStore; now: () => Date; memo: Map<string, Promise<unknown>> }`
  - `subjectId(s)`, `subjectKind(s)`, `subjectHostname(s)`
  - `memoize(ctx, key, fn)`
  - `interface Page { obs: HttpObservation; evidenceId: string }`, `getPage(ctx, subject, url?): Promise<Page>`
  - test helpers:
    - `FIXED_NOW`, `fakeObs(partial?)`
    - `makeCtx(net?, projectOverrides?) → { ctx, dir }`
    - `targetSubject(ctx)`, `hostSubject(ctx)`

- [ ] **Step 1: Write the test helper and the failing tests**

`test/helpers/ctx.ts`:
```ts
import type { CheckContext, CheckSubject } from '../../src/checks/context.js';
import { EvidenceStore } from '../../src/evidence/store.js';
import type { HttpObservation } from '../../src/net/http.js';
import type { NetClient } from '../../src/net/scoped.js';
import { validateProject } from '../../src/project/schema.js';
import { tempDir } from './tmp.js';

export const FIXED_NOW = new Date('2026-10-28T10:00:00.000Z');

export function fakeObs(partial: Partial<HttpObservation> = {}): HttpObservation {
  return {
    url: 'https://app.example.com/',
    status: 200,
    headers: {},
    setCookies: [],
    headerBytes: 200,
    bodySnippet: '',
    bodyBytes: 0,
    ...partial,
  };
}

const unstubbed = (name: string) => async (): Promise<never> => {
  throw new Error(`net.${name} was not stubbed in this test`);
};

/** A context with one web target "app" (https://app.example.com) and one host "web-1" (203.0.113.10). */
export async function makeCtx(
  net: Partial<NetClient> = {},
  projectOverrides: Record<string, unknown> = {},
): Promise<{ ctx: CheckContext; dir: string }> {
  const dir = await tempDir();
  const project = validateProject({
    version: 1,
    name: 'test',
    network: { scan_label: 'test-net' },
    targets: [{ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' }],
    hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod', reachable_from: ['office'] }],
    ...projectOverrides,
  });
  const ctx: CheckContext = {
    project,
    net: { http: unstubbed('http'), tls: unstubbed('tls'), tcp: unstubbed('tcp'), ...net },
    evidence: new EvidenceStore(dir, project.network.scan_label, () => FIXED_NOW),
    now: () => FIXED_NOW,
    memo: new Map(),
  };
  return { ctx, dir };
}

export function targetSubject(ctx: CheckContext): Extract<CheckSubject, { kind: 'target' }> {
  const target = ctx.project.targets[0];
  if (!target) throw new Error('test project has no target');
  return { kind: 'target', target };
}

export function hostSubject(ctx: CheckContext): Extract<CheckSubject, { kind: 'host' }> {
  const host = ctx.project.hosts[0];
  if (!host) throw new Error('test project has no host');
  return { kind: 'host', host };
}
```

`test/net/scoped.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { NetError } from '../../src/net/errors.js';
import { ScopedNet, withRetry } from '../../src/net/scoped.js';
import { validateProject } from '../../src/project/schema.js';
import { Scope, ScopeError } from '../../src/project/scope.js';
import { startHttp } from '../helpers/servers.js';

describe('ScopedNet', () => {
  it('refuses unlisted hosts before opening a connection, and allows listed ones', async () => {
    const s = await startHttp((_req, res) => res.end('ok'));
    try {
      const project = validateProject({
        version: 1,
        name: 't',
        targets: [{ id: 'local', url: `http://127.0.0.1:${s.port}`, type: 'web', env: 'test' }],
      });
      const net = new ScopedNet(new Scope(project), 4);
      await expect(net.http('http://127.0.0.2/')).rejects.toBeInstanceOf(ScopeError);
      await expect(net.tcp('127.0.0.2', 80)).rejects.toBeInstanceOf(ScopeError);
      expect((await net.http(`${s.url}/`)).status).toBe(200);
      expect(await net.tcp('127.0.0.1', s.port)).toBe('open');
    } finally {
      await s.close();
    }
  });
});

describe('withRetry', () => {
  it('retries once on a timeout', async () => {
    let calls = 0;
    const result = await withRetry(async () => {
      calls += 1;
      if (calls === 1) throw new NetError('TIMEOUT', 'slow');
      return 'ok';
    });
    expect(result).toBe('ok');
    expect(calls).toBe(2);
  });

  it('does not retry other errors', async () => {
    let calls = 0;
    await expect(
      withRetry(async () => {
        calls += 1;
        throw new NetError('ECONNREFUSED', 'no');
      }),
    ).rejects.toMatchObject({ code: 'ECONNREFUSED' });
    expect(calls).toBe(1);
  });
});
```

`test/evidence/store.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { EVIDENCE_ID_PATTERN, EvidenceStore, newEvidenceId } from '../../src/evidence/store.js';
import { tempDir } from '../helpers/tmp.js';

describe('EvidenceStore', () => {
  it('formats ids from the capture time', () => {
    const id = newEvidenceId(new Date('2026-10-28T10:15:00.123Z'));
    expect(id).toMatch(/^ev_20261028T101500Z_[0-9a-f]{8}$/);
    expect(EVIDENCE_ID_PATTERN.test(id)).toBe(true);
  });

  it('round-trips a record with scan label and timestamp', async () => {
    const dir = await tempDir();
    const store = new EvidenceStore(dir, 'office', () => new Date('2026-10-28T10:00:00.000Z'));
    const id = await store.put('http', 'app', 'GET / → 200', { status: 200 });
    expect(await store.get(id)).toEqual({
      id,
      kind: 'http',
      target: 'app',
      scan_label: 'office',
      captured_at: '2026-10-28T10:00:00.000Z',
      summary: 'GET / → 200',
      data: { status: 200 },
    });
  });

  it('rejects ids that are not evidence ids (no path traversal)', async () => {
    const store = new EvidenceStore(await tempDir(), 'office');
    await expect(store.get('../../etc/passwd')).rejects.toThrow(/Invalid evidence id/);
  });
});
```

`test/checks/context.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { getPage, subjectHostname, subjectId, subjectKind } from '../../src/checks/context.js';
import { fakeObs, hostSubject, makeCtx, targetSubject } from '../helpers/ctx.js';

describe('check context', () => {
  it('fetches a target page once per scan and shares its evidence', async () => {
    let calls = 0;
    const { ctx } = await makeCtx({
      http: async (url) => {
        calls += 1;
        return fakeObs({ url });
      },
    });
    const a = await getPage(ctx, targetSubject(ctx));
    const b = await getPage(ctx, targetSubject(ctx));
    expect(calls).toBe(1);
    expect(a.evidenceId).toBe(b.evidenceId);
  });

  it('describes subjects', async () => {
    const { ctx } = await makeCtx();
    expect(subjectId(targetSubject(ctx))).toBe('app');
    expect(subjectKind(targetSubject(ctx))).toBe('web');
    expect(subjectHostname(targetSubject(ctx))).toBe('app.example.com');
    expect(subjectId(hostSubject(ctx))).toBe('web-1');
    expect(subjectKind(hostSubject(ctx))).toBe('host');
    expect(subjectHostname(hostSubject(ctx))).toBe('203.0.113.10');
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/net/scoped.test.ts test/evidence/store.test.ts test/checks/context.test.ts`
Expected: FAIL, because the modules can't be resolved.

- [ ] **Step 3: Implement `src/net/scoped.ts`, `src/evidence/store.ts`, `src/checks/context.ts`**

`src/net/scoped.ts`:
```ts
import type { Scope } from '../project/scope.js';
import { NetError } from './errors.js';
import { httpRequest, type HttpObservation, type HttpOptions } from './http.js';
import { tcpProbe, type PortState } from './tcp.js';
import { tlsHandshake, type TlsObservation, type TlsOptions } from './tls.js';

/** The only network access a check gets. */
export interface NetClient {
  http(url: string, opts?: Pick<HttpOptions, 'method' | 'headers'>): Promise<HttpObservation>;
  tls(host: string, port: number, opts?: Pick<TlsOptions, 'minVersion' | 'maxVersion' | 'ciphers' | 'servername'>): Promise<TlsObservation>;
  tcp(host: string, port: number): Promise<PortState>;
}

const RETRYABLE = new Set(['TIMEOUT', 'CONNECT_TIMEOUT']);

export async function withRetry<T>(fn: () => Promise<T>, retries = 1): Promise<T> {
  for (let attempt = 0; ; attempt += 1) {
    try {
      return await fn();
    } catch (e) {
      if (attempt >= retries || !(e instanceof NetError) || !RETRYABLE.has(e.code)) throw e;
    }
  }
}

/** Every call is scope-checked first, so no check can reach a host that project.yaml does not list. */
export class ScopedNet implements NetClient {
  constructor(
    private readonly scope: Scope,
    private readonly family: 4 | 6,
    private readonly timeouts: { totalMs: number; connectMs: number } = { totalMs: 10_000, connectMs: 5_000 },
  ) {}

  async http(url: string, opts: Pick<HttpOptions, 'method' | 'headers'> = {}): Promise<HttpObservation> {
    await this.scope.assertUrlAllowed(url);
    return withRetry(() =>
      httpRequest(url, { family: this.family, timeoutMs: this.timeouts.totalMs, connectTimeoutMs: this.timeouts.connectMs, ...opts }),
    );
  }

  async tls(
    host: string,
    port: number,
    opts: Pick<TlsOptions, 'minVersion' | 'maxVersion' | 'ciphers' | 'servername'> = {},
  ): Promise<TlsObservation> {
    await this.scope.assertHostnameAllowed(host);
    return withRetry(() => tlsHandshake(host, port, { family: this.family, timeoutMs: this.timeouts.totalMs, ...opts }));
  }

  async tcp(host: string, port: number): Promise<PortState> {
    await this.scope.assertHostnameAllowed(host);
    return tcpProbe(host, port, { family: this.family, timeoutMs: this.timeouts.connectMs });
  }
}
```

`src/evidence/store.ts`:
```ts
import { randomBytes } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { projectStateDir } from '../paths.js';

export type EvidenceKind = 'http' | 'tls' | 'tcp' | 'note';

export interface EvidenceRecord {
  id: string;
  kind: EvidenceKind;
  /** Target id or host name. */
  target: string;
  /** Network the observation was made from (project.yaml network.scan_label). */
  scan_label: string;
  captured_at: string;
  summary: string;
  data: unknown;
}

export const EVIDENCE_ID_PATTERN = /^ev_\d{8}T\d{6}Z_[0-9a-f]{8}$/;

export function newEvidenceId(now: Date): string {
  const stamp = now.toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
  return `ev_${stamp}_${randomBytes(4).toString('hex')}`;
}

export class EvidenceStore {
  readonly dir: string;

  constructor(
    projectDir: string,
    private readonly scanLabel: string,
    private readonly now: () => Date = () => new Date(),
  ) {
    this.dir = path.join(projectStateDir(projectDir), 'evidence');
  }

  async put(kind: EvidenceKind, target: string, summary: string, data: unknown): Promise<string> {
    const at = this.now();
    const id = newEvidenceId(at);
    const record: EvidenceRecord = { id, kind, target, scan_label: this.scanLabel, captured_at: at.toISOString(), summary, data };
    await mkdir(this.dir, { recursive: true });
    await writeFile(path.join(this.dir, `${id}.json`), `${JSON.stringify(record, null, 2)}\n`, 'utf8');
    return id;
  }

  async get(id: string): Promise<EvidenceRecord> {
    if (!EVIDENCE_ID_PATTERN.test(id)) throw new Error(`Invalid evidence id "${id}"`);
    return JSON.parse(await readFile(path.join(this.dir, `${id}.json`), 'utf8')) as EvidenceRecord;
  }
}
```

`src/checks/context.ts`:
```ts
import type { EvidenceStore } from '../evidence/store.js';
import type { HttpObservation } from '../net/http.js';
import { stripBrackets } from '../net/ip.js';
import type { NetClient } from '../net/scoped.js';
import type { Host, ProjectConfig, Target } from '../project/schema.js';
import type { SubjectKind } from '../types.js';

export type CheckSubject = { kind: 'target'; target: Target } | { kind: 'host'; host: Host };

export interface CheckContext {
  project: ProjectConfig;
  net: NetClient;
  evidence: EvidenceStore;
  now: () => Date;
  /** Per-scan cache so checks sharing an observation (e.g. the target's page) fetch it once. */
  memo: Map<string, Promise<unknown>>;
}

export function subjectId(subject: CheckSubject): string {
  return subject.kind === 'target' ? subject.target.id : subject.host.name;
}

export function subjectKind(subject: CheckSubject): SubjectKind {
  return subject.kind === 'target' ? subject.target.type : 'host';
}

/** Hostname or address that network probes for this subject go to. */
export function subjectHostname(subject: CheckSubject): string {
  return subject.kind === 'target' ? stripBrackets(new URL(subject.target.url).hostname) : subject.host.address;
}

export function memoize<T>(ctx: CheckContext, key: string, fn: () => Promise<T>): Promise<T> {
  let pending = ctx.memo.get(key) as Promise<T> | undefined;
  if (!pending) {
    pending = fn();
    ctx.memo.set(key, pending);
  }
  return pending;
}

export interface Page {
  obs: HttpObservation;
  evidenceId: string;
}

/** GET a target URL once per scan; header, cookie and budget checks share the observation and its evidence. */
export function getPage(
  ctx: CheckContext,
  subject: Extract<CheckSubject, { kind: 'target' }>,
  url: string = subject.target.url,
): Promise<Page> {
  return memoize(ctx, `GET ${url}`, async () => {
    const obs = await ctx.net.http(url);
    const evidenceId = await ctx.evidence.put('http', subject.target.id, `GET ${url} → ${obs.status}`, obs);
    return { obs, evidenceId };
  });
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/net/scoped.test.ts test/evidence/store.test.ts test/checks/context.test.ts && npx tsc -p tsconfig.json`
Expected: 8 tests PASS; `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/net/scoped.ts src/evidence/store.ts src/checks/context.ts test/helpers/ctx.ts test/net/scoped.test.ts test/evidence/store.test.ts test/checks/context.test.ts
git commit -m "feat(checks): add scoped network client, evidence store and check context"
```

---

### Task 9: Check catalog, registry and runner

**Files:**
- Create: `src/checks/check-type.ts`, `src/checks/catalog.ts`, `src/checks/registry.ts`, `src/checks/runner.ts`
- Test: `test/checks/catalog.test.ts`, `test/checks/runner.test.ts`

**Interfaces:**
- Consumes: `CheckContext`, `CheckSubject`, `subjectId`, `subjectKind` (Task 8); `NetError` (Task 5); `ScopeError` (Task 5); `SEVERITIES`, `SUBJECT_KINDS`, types (Task 1)
- Produces:
  - `interface CheckOutput { outcome: Outcome; observed: string; evidence_id: string; severity?: Severity; details? }`
  - `interface CheckType<P>`:
    - `type: string; supports: readonly SubjectKind[]; params: z.ZodType<P>`
    - `run(ctx, subject, params: P, instance: CheckInstance): Promise<CheckOutput>`
  - `type AnyCheckType = CheckType<any>`
  - `CheckInstanceSchema`, `type CheckInstance`, `class CatalogError`
  - `loadCheckInstances(dir, knownTypes: ReadonlyMap<string, AnyCheckType>): Promise<CheckInstance[]>` (instance `params` are replaced by the type-parsed params)
  - `CHECK_TYPES: ReadonlyMap<string, AnyCheckType>` (empty until Tasks 10–14 register types)
  - `applicableInstances(instances, subject)`
  - `runInstance(ctx, subject, instance, types): Promise<CheckResult>`
  - `runChecks(ctx, subject, instances, types): Promise<CheckResult[]>`

- [ ] **Step 1: Write the failing tests**

`test/checks/catalog.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { CatalogError, loadCheckInstances } from '../../src/checks/catalog.js';
import type { AnyCheckType } from '../../src/checks/check-type.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

const fake: AnyCheckType = {
  type: 'fake',
  supports: ['web'],
  params: z.object({ limit: z.number().default(5) }),
  run: async () => {
    throw new Error('not run in catalog tests');
  },
};
const TYPES = new Map([['fake', fake]]);

const instance = (extra = '') => `id: fake-one
type: fake
title: Fake check
severity: low
applies_to: [web]
source_url: https://example.com/guide
review: approved
${extra}`;

describe('loadCheckInstances', () => {
  it('loads instances and applies the type param defaults', async () => {
    const dir = await tempDir();
    await writeFiles(dir, { 'fake-one.yaml': instance(), 'README.md': 'ignored' });
    const [one] = await loadCheckInstances(dir, TYPES);
    expect(one).toMatchObject({ id: 'fake-one', params: { limit: 5 }, added_by: 'seed', fix_hints: {}, side_effects: [] });
  });

  it('collects every problem into one CatalogError', async () => {
    const dir = await tempDir();
    await writeFiles(dir, {
      'a.yaml': instance().replace('type: fake', 'type: nope'),
      'b.yaml': instance('params:\n  limit: "five"\n').replace('fake-one', 'fake-two'),
      'c.yaml': `${instance().replace('fake-one', 'fake-three')}added_by: learn-2026-10-28\n`,
    });
    const err = await loadCheckInstances(dir, TYPES).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(CatalogError);
    const message = (err as Error).message;
    expect(message).toContain('a.yaml: unknown check type "nope"');
    expect(message).toContain('b.yaml: params.limit');
    expect(message).toContain('c.yaml: quote');
  });

  it('rejects duplicate ids', async () => {
    const dir = await tempDir();
    await writeFiles(dir, { 'a.yaml': instance(), 'b.yaml': instance() });
    await expect(loadCheckInstances(dir, TYPES)).rejects.toThrow(/duplicate check id "fake-one"/);
  });
});
```

`test/checks/runner.test.ts`:
```ts
import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { CheckInstanceSchema, type CheckInstance } from '../../src/checks/catalog.js';
import type { AnyCheckType, CheckType } from '../../src/checks/check-type.js';
import { subjectId } from '../../src/checks/context.js';
import { runChecks, runInstance } from '../../src/checks/runner.js';
import { NetError } from '../../src/net/errors.js';
import { hostSubject, makeCtx, targetSubject } from '../helpers/ctx.js';

type Mode = 'pass' | 'fail' | 'neterror' | 'boom';
const fakeType: CheckType<{ mode: Mode }> = {
  type: 'fake',
  supports: ['web', 'api', 'host'],
  params: z.object({ mode: z.enum(['pass', 'fail', 'neterror', 'boom']) }),
  async run(ctx, subject, p) {
    if (p.mode === 'neterror') throw new NetError('TIMEOUT', 'too slow');
    if (p.mode === 'boom') throw new Error('bug in check');
    const evidence_id = await ctx.evidence.put('note', subjectId(subject), `fake ${p.mode}`, {});
    return { outcome: p.mode, observed: `fake ${p.mode}`, evidence_id, ...(p.mode === 'fail' ? { severity: 'high' as const } : {}) };
  },
};
const TYPES = new Map<string, AnyCheckType>([['fake', fakeType]]);

function inst(id: string, mode: Mode, applies_to: string[] = ['web']): CheckInstance {
  return CheckInstanceSchema.parse({
    id,
    type: 'fake',
    title: id,
    severity: 'low',
    applies_to,
    params: { mode },
    source_url: 'https://example.com/guide',
    review: 'approved',
  });
}

describe('runInstance', () => {
  it('passes results through with the instance default severity', async () => {
    const { ctx } = await makeCtx();
    const r = await runInstance(ctx, targetSubject(ctx), inst('a', 'pass'), TYPES);
    expect(r).toMatchObject({ check_id: 'a', target: 'app', title: 'a', outcome: 'pass', severity: 'low', observed: 'fake pass' });
  });

  it('lets a check raise severity', async () => {
    const { ctx } = await makeCtx();
    expect((await runInstance(ctx, targetSubject(ctx), inst('a', 'fail'), TYPES)).severity).toBe('high');
  });

  it('turns network errors into unverifiable, with evidence and a reachability hint', async () => {
    const { ctx, dir } = await makeCtx();
    const r = await runInstance(ctx, hostSubject(ctx), inst('a', 'neterror', ['host']), TYPES);
    expect(r.outcome).toBe('unverifiable');
    expect(r.observed).toContain('test-net');
    expect(r.observed).toContain('office');
    expect(r.observed).toContain('does not mean the issue is fixed');
    expect(existsSync(path.join(dir, '.secagent', 'evidence', `${r.evidence_id}.json`))).toBe(true);
  });

  it('turns check bugs into error', async () => {
    const { ctx } = await makeCtx();
    const r = await runInstance(ctx, targetSubject(ctx), inst('a', 'boom'), TYPES);
    expect(r.outcome).toBe('error');
    expect(r.observed).toContain('bug in check');
  });
});

describe('runChecks', () => {
  it('runs only the instances that apply to the subject kind', async () => {
    const { ctx } = await makeCtx();
    const instances = [inst('web-only', 'pass', ['web']), inst('host-only', 'pass', ['host'])];
    expect((await runChecks(ctx, targetSubject(ctx), instances, TYPES)).map((r) => r.check_id)).toEqual(['web-only']);
    expect((await runChecks(ctx, hostSubject(ctx), instances, TYPES)).map((r) => r.check_id)).toEqual(['host-only']);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/checks/catalog.test.ts test/checks/runner.test.ts`
Expected: FAIL, because the modules can't be resolved.

- [ ] **Step 3: Implement `check-type.ts`, `catalog.ts`, `registry.ts`, `runner.ts`**

`src/checks/check-type.ts`:
```ts
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
```

`src/checks/catalog.ts`:
```ts
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import { parse } from 'yaml';
import { z } from 'zod';
import { SEVERITIES, SUBJECT_KINDS } from '../types.js';
import type { AnyCheckType } from './check-type.js';

export const CheckInstanceSchema = z
  .object({
    id: z.string().regex(/^[a-z0-9][a-z0-9-]*$/),
    type: z.string().min(1),
    title: z.string().min(1),
    severity: z.enum(SEVERITIES),
    applies_to: z.array(z.enum(SUBJECT_KINDS)).min(1),
    params: z.record(z.string(), z.unknown()).default({}),
    fix_hints: z.record(z.string(), z.string()).default({}),
    side_effects: z.array(z.string()).default([]),
    source_url: z.url({ protocol: /^https$/ }),
    quote: z.string().optional(),
    added_by: z.string().default('seed'),
    review: z.enum(['approved', 'pending']),
    reviewed_by: z.string().optional(),
    reviewed_at: z.string().optional(),
  })
  .refine((c) => c.added_by === 'seed' || c.quote !== undefined, {
    message: 'learned check instances must carry a verbatim quote from their source',
    path: ['quote'],
  });

export type CheckInstance = z.infer<typeof CheckInstanceSchema>;

export class CatalogError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CatalogError';
  }
}

/** Loads every *.yaml instance in dir, validating it and its params against the registered type. */
export async function loadCheckInstances(dir: string, knownTypes: ReadonlyMap<string, AnyCheckType>): Promise<CheckInstance[]> {
  const files = (await readdir(dir)).filter((f) => f.endsWith('.yaml') || f.endsWith('.yml')).sort();
  const instances: CheckInstance[] = [];
  const errors: string[] = [];
  const ids = new Set<string>();

  for (const file of files) {
    let raw: unknown;
    try {
      raw = parse(await readFile(path.join(dir, file), 'utf8'));
    } catch (e) {
      errors.push(`${file}: invalid YAML: ${(e as Error).message}`);
      continue;
    }
    const parsed = CheckInstanceSchema.safeParse(raw);
    if (!parsed.success) {
      errors.push(...parsed.error.issues.map((i) => `${file}: ${i.path.join('.') || '(root)'}: ${i.message}`));
      continue;
    }
    const type = knownTypes.get(parsed.data.type);
    if (!type) {
      errors.push(`${file}: unknown check type "${parsed.data.type}"`);
      continue;
    }
    const params = type.params.safeParse(parsed.data.params);
    if (!params.success) {
      errors.push(...params.error.issues.map((i) => `${file}: params.${i.path.join('.')}: ${i.message}`));
      continue;
    }
    if (ids.has(parsed.data.id)) {
      errors.push(`${file}: duplicate check id "${parsed.data.id}"`);
      continue;
    }
    ids.add(parsed.data.id);
    instances.push({ ...parsed.data, params: params.data as Record<string, unknown> });
  }

  if (errors.length > 0) {
    throw new CatalogError(`Invalid check catalog in ${dir}:\n${errors.map((e) => `  - ${e}`).join('\n')}`);
  }
  return instances;
}
```

`src/checks/registry.ts`:
```ts
import type { AnyCheckType } from './check-type.js';

/** Every check type the engine knows. Learning may add YAML instances of these types, never new types. */
const ALL: AnyCheckType[] = [];

export const CHECK_TYPES: ReadonlyMap<string, AnyCheckType> = new Map(ALL.map((t) => [t.type, t]));
```

`src/checks/runner.ts`:
```ts
import { NetError } from '../net/errors.js';
import { ScopeError } from '../project/scope.js';
import type { CheckResult } from '../types.js';
import type { CheckInstance } from './catalog.js';
import type { AnyCheckType } from './check-type.js';
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
    const unverifiable = e instanceof NetError || e instanceof ScopeError;
    const code = e instanceof NetError ? e.code : e instanceof ScopeError ? 'OUT_OF_SCOPE' : 'CHECK_ERROR';
    const label = ctx.project.network.scan_label;
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
): Promise<CheckResult[]> {
  const results: CheckResult[] = [];
  for (const instance of applicableInstances(instances, subject)) {
    results.push(await runInstance(ctx, subject, instance, types));
  }
  return results;
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/checks/catalog.test.ts test/checks/runner.test.ts && npx tsc -p tsconfig.json`
Expected: 8 tests PASS; `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/checks/check-type.ts src/checks/catalog.ts src/checks/registry.ts src/checks/runner.ts test/checks/catalog.test.ts test/checks/runner.test.ts
git commit -m "feat(checks): add YAML check catalog, type registry and runner"
```

---

### Task 10: `http_redirect` and `http_header` check types with seed instances

**Files:**
- Create: `src/checks/types/http-redirect.ts`, `src/checks/types/http-header.ts`
- Create: `knowledge/checks/http-redirect-https.yaml`, `hdr-hsts.yaml`, `hdr-csp.yaml`, `hdr-frame-options.yaml`, `hdr-content-type-options.yaml`, `hdr-referrer-policy.yaml`, `hdr-permissions-policy.yaml`, `hdr-x-powered-by.yaml`, `hdr-server-version.yaml`
- Modify: `src/checks/registry.ts`
- Test: `test/checks/types/http-redirect.test.ts`, `test/checks/types/http-header.test.ts`, `test/checks/seed-catalog.test.ts`

**Interfaces:**
- Consumes: `CheckType` (Task 9); `getPage`, `CheckContext` (Task 8); `HttpObservation` (Task 6); `NetError` (Task 5); test helpers `makeCtx`, `fakeObs`, `targetSubject` (Task 8)
- Produces:
  - `httpRedirectParams`, `evaluateRedirect(obs, expectedHostname, params)`, `httpRedirectCheck`
  - `httpHeaderParams`, `type HttpHeaderParams`, `parseCsp(value): Map<string, string[]>`, `evaluateHeader(obs, params)`, `httpHeaderCheck`

- [ ] **Step 1: Write the failing tests**

`test/checks/types/http-redirect.test.ts`:
```ts
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
```

`test/checks/types/http-header.test.ts`:
```ts
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
```

`test/checks/seed-catalog.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { loadCheckInstances } from '../../src/checks/catalog.js';
import { CHECK_TYPES } from '../../src/checks/registry.js';
import { GLOBAL_CHECKS_DIR } from '../../src/paths.js';

describe('seed check catalog', () => {
  it('loads every seed instance against the registered types', async () => {
    const instances = await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES);
    expect(instances.length).toBeGreaterThan(0);
    for (const i of instances) {
      expect(i.review).toBe('approved');
      expect(i.added_by).toBe('seed');
      const type = CHECK_TYPES.get(i.type);
      expect(type).toBeDefined();
      for (const kind of i.applies_to) expect(type?.supports).toContain(kind);
    }
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/checks/types/http-redirect.test.ts test/checks/types/http-header.test.ts test/checks/seed-catalog.test.ts`
Expected: FAIL, because the type modules can't be resolved, and `knowledge/checks` doesn't exist (`ENOENT`).

- [ ] **Step 3: Implement the two check types**

`src/checks/types/http-redirect.ts`:
```ts
import { z } from 'zod';
import { NetError } from '../../net/errors.js';
import type { HttpObservation } from '../../net/http.js';
import { stripBrackets } from '../../net/ip.js';
import type { CheckType } from '../check-type.js';

export const httpRedirectParams = z.object({
  accepted_statuses: z.array(z.number().int()).default([301, 308]),
});
export type HttpRedirectParams = z.infer<typeof httpRedirectParams>;

export function evaluateRedirect(
  obs: HttpObservation,
  expectedHostname: string,
  p: HttpRedirectParams,
): { outcome: 'pass' | 'fail'; observed: string } {
  if (obs.status < 300 || obs.status >= 400 || !obs.location) {
    return { outcome: 'fail', observed: `http:// answered ${obs.status} without redirecting to https:// (content is served over plaintext)` };
  }
  let location: URL;
  try {
    location = new URL(obs.location, obs.url);
  } catch {
    return { outcome: 'fail', observed: `redirect Location is not a valid URL: ${obs.location}` };
  }
  if (location.protocol !== 'https:') {
    return { outcome: 'fail', observed: `http:// redirects to ${location.href}, which is not https://` };
  }
  if (stripBrackets(location.hostname).toLowerCase() !== expectedHostname.toLowerCase()) {
    return {
      outcome: 'fail',
      observed: `http:// redirects to a different host (${location.hostname}); the first hop should stay on ${expectedHostname} so HSTS applies`,
    };
  }
  if (!p.accepted_statuses.includes(obs.status)) {
    return { outcome: 'fail', observed: `http:// redirects to https:// with ${obs.status}; use a permanent redirect (${p.accepted_statuses.join('/')})` };
  }
  return { outcome: 'pass', observed: `http:// → ${obs.status} → ${location.href}` };
}

export const httpRedirectCheck: CheckType<HttpRedirectParams> = {
  type: 'http_redirect',
  supports: ['web', 'api'],
  params: httpRedirectParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'target') throw new Error('http_redirect runs on targets only');
    const target = new URL(subject.target.url);
    const httpUrl = target.protocol === 'http:' ? subject.target.url : `http://${target.hostname}/`;
    let obs: HttpObservation;
    try {
      obs = await ctx.net.http(httpUrl);
    } catch (e) {
      if (e instanceof NetError && e.code === 'ECONNREFUSED') {
        const evidence_id = await ctx.evidence.put('note', subject.target.id, `${httpUrl} refused the connection`, { url: httpUrl, code: e.code });
        return { outcome: 'pass', observed: 'port 80 refuses connections, so nothing is served over plaintext HTTP', evidence_id };
      }
      throw e;
    }
    const evidence_id = await ctx.evidence.put('http', subject.target.id, `GET ${httpUrl} → ${obs.status}`, obs);
    return { ...evaluateRedirect(obs, stripBrackets(target.hostname), p), evidence_id };
  },
};
```

`src/checks/types/http-header.ts`:
```ts
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
```

- [ ] **Step 4: Register both types in `src/checks/registry.ts`**

Replace the file with:
```ts
import type { AnyCheckType } from './check-type.js';
import { httpHeaderCheck } from './types/http-header.js';
import { httpRedirectCheck } from './types/http-redirect.js';

/** Every check type the engine knows. Learning may add YAML instances of these types, never new types. */
const ALL: AnyCheckType[] = [httpRedirectCheck, httpHeaderCheck];

export const CHECK_TYPES: ReadonlyMap<string, AnyCheckType> = new Map(ALL.map((t) => [t.type, t]));
```

- [ ] **Step 5: Write the nine seed instances**

`knowledge/checks/http-redirect-https.yaml`:
```yaml
id: http-redirect-https
type: http_redirect
title: Plain HTTP permanently redirects to HTTPS on the same host
severity: high
applies_to: [web, api]
params:
  accepted_statuses: [301, 308]
fix_hints:
  nginx: 'server { listen 80; server_name _; return 301 https://$host$request_uri; }'
  vercel: 'Vercel redirects HTTP to HTTPS automatically; confirm every custom domain is attached to the project.'
  any: 'If a load balancer terminates TLS, add an HTTP:80 listener rule that redirects to HTTPS:443 with status 301.'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/hdr-hsts.yaml`:
```yaml
id: hdr-hsts
type: http_header
title: HSTS enabled with max-age of at least 180 days
severity: medium
applies_to: [web, api]
params:
  header: strict-transport-security
  must_exist: true
  min_max_age: 15552000
fix_hints:
  nginx: 'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;'
  express: 'app.use(helmet.hsts({ maxAge: 31536000, includeSubDomains: true }))'
  nestjs: 'app.use(helmet()) in main.ts (helmet sends HSTS by default)'
  nextjs: 'headers() in next.config: { key: "Strict-Transport-Security", value: "max-age=31536000; includeSubDomains" }'
  vercel: 'Vercel sends HSTS on its domains; set it explicitly in vercel.json headers for custom values.'
side_effects: [header-budget-proxy-buffer]
source_url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/hdr-csp.yaml`:
```yaml
id: hdr-csp
type: http_header
title: Content-Security-Policy restricts script sources
severity: medium
applies_to: [web]
params:
  header: content-security-policy
  must_exist: true
  csp_forbid:
    directive: script-src
    fallback: default-src
    tokens: ["'unsafe-inline'", "'unsafe-eval'", '*', 'http:', 'https:', 'data:']
fix_hints:
  nginx: "add_header Content-Security-Policy \"default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'\" always;"
  angular: 'Set the header in nginx or the CDN. AOT builds need no inline scripts; if one is required, use a CSP nonce (ngCspNonce).'
  vue: 'Set the header in nginx or the CDN; Vite production builds do not need inline scripts.'
  nextjs: 'headers() in next.config, or middleware that adds a per-request nonce for inline scripts.'
  express: "app.use(helmet.contentSecurityPolicy({ directives: { scriptSrc: [\"'self'\"] } }))"
  nestjs: "app.use(helmet({ contentSecurityPolicy: { directives: { scriptSrc: [\"'self'\"] } } })) in main.ts"
side_effects: [header-budget-proxy-buffer]
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Content_Security_Policy_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/hdr-frame-options.yaml`:
```yaml
id: hdr-frame-options
type: http_header
title: Framing is restricted (X-Frame-Options or CSP frame-ancestors)
severity: medium
applies_to: [web]
params:
  header: x-frame-options
  must_exist: true
  one_of: [deny, sameorigin]
  satisfied_by_csp_directive: frame-ancestors
fix_hints:
  nginx: "add_header X-Frame-Options \"DENY\" always;  # or CSP: frame-ancestors 'none'"
  express: "app.use(helmet.frameguard({ action: 'deny' }))"
  nestjs: 'app.use(helmet()) in main.ts'
  nextjs: 'headers() in next.config: { key: "X-Frame-Options", value: "DENY" }'
side_effects: [header-budget-proxy-buffer]
source_url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/hdr-content-type-options.yaml`:
```yaml
id: hdr-content-type-options
type: http_header
title: X-Content-Type-Options is nosniff
severity: low
applies_to: [web, api]
params:
  header: x-content-type-options
  must_exist: true
  equals: nosniff
fix_hints:
  nginx: 'add_header X-Content-Type-Options "nosniff" always;'
  express: 'app.use(helmet.noSniff())'
  nestjs: 'app.use(helmet()) in main.ts'
  nextjs: 'headers() in next.config: { key: "X-Content-Type-Options", value: "nosniff" }'
side_effects: [header-budget-proxy-buffer]
source_url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/hdr-referrer-policy.yaml`:
```yaml
id: hdr-referrer-policy
type: http_header
title: Referrer-Policy limits what is sent to other sites
severity: low
applies_to: [web]
params:
  header: referrer-policy
  must_exist: true
  one_of: [no-referrer, same-origin, strict-origin, strict-origin-when-cross-origin]
fix_hints:
  nginx: 'add_header Referrer-Policy "strict-origin-when-cross-origin" always;'
  express: "app.use(helmet.referrerPolicy({ policy: 'strict-origin-when-cross-origin' }))"
  nestjs: 'app.use(helmet()) in main.ts'
  nextjs: 'headers() in next.config: { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" }'
side_effects: [header-budget-proxy-buffer]
source_url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/hdr-permissions-policy.yaml`:
```yaml
id: hdr-permissions-policy
type: http_header
title: Permissions-Policy disables unused browser features
severity: low
applies_to: [web]
params:
  header: permissions-policy
  must_exist: true
fix_hints:
  nginx: 'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;'
  express: "app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'); next(); })"
  nestjs: "app.use((req, res, next) => { res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()'); next(); }) in main.ts"
  nextjs: 'headers() in next.config: { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" }'
side_effects: [header-budget-proxy-buffer]
source_url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/hdr-x-powered-by.yaml`:
```yaml
id: hdr-x-powered-by
type: http_header
title: X-Powered-By is not sent
severity: low
applies_to: [web, api]
params:
  header: x-powered-by
  must_not_exist: true
fix_hints:
  nginx: 'proxy_hide_header X-Powered-By;'
  express: "app.disable('x-powered-by')  // or app.use(helmet())"
  nestjs: "app.getHttpAdapter().getInstance().disable('x-powered-by')  // or app.use(helmet())"
  nextjs: 'poweredByHeader: false in next.config'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/hdr-server-version.yaml`:
```yaml
id: hdr-server-version
type: http_header
title: Server header does not disclose a version
severity: low
applies_to: [web, api]
params:
  header: server
  forbid_pattern: '\d'
fix_hints:
  nginx: 'server_tokens off;  (http block)'
  any: 'Version banners let scanners match CVEs by version. Hide them, and patch via the distro regardless.'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
added_by: seed
review: approved
```

- [ ] **Step 6: Run tests and typecheck**

Run: `npx vitest run test/checks && npx tsc -p tsconfig.json`
Expected: all tests in `test/checks/` PASS, including the seed catalog test loading 9 instances; `tsc` exits 0.

- [ ] **Step 7: Commit**

```bash
git add src/checks/types/http-redirect.ts src/checks/types/http-header.ts src/checks/registry.ts knowledge/checks test/checks/types/http-redirect.test.ts test/checks/types/http-header.test.ts test/checks/seed-catalog.test.ts
git commit -m "feat(checks): add http_redirect and http_header types with seed instances"
```

---

### Task 11: `http_cookie` and `header_budget` check types

**Files:**
- Create: `src/checks/types/http-cookie.ts`, `src/checks/types/header-budget.ts`, `knowledge/checks/cookie-flags.yaml`, `knowledge/checks/header-budget.yaml`
- Modify: `src/checks/registry.ts`
- Test: `test/checks/types/http-cookie.test.ts`, `test/checks/types/header-budget.test.ts`

**Interfaces:**
- Consumes: `CheckType` (Task 9); `getPage` (Task 8); `HttpObservation` (Task 6); `Severity` (Task 1)
- Produces:
  - `httpCookieParams`, `evaluateCookies(obs, params)`, `httpCookieCheck`
  - `headerBudgetParams`, `evaluateBudget(obs, params): { outcome; observed; severity? }`, `headerBudgetCheck`

- [ ] **Step 1: Write the failing tests**

`test/checks/types/http-cookie.test.ts`:
```ts
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
});
```

`test/checks/types/header-budget.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { evaluateBudget, headerBudgetParams } from '../../../src/checks/types/header-budget.js';
import { fakeObs } from '../../helpers/ctx.js';

const P = headerBudgetParams.parse({});

describe('evaluateBudget', () => {
  it('passes comfortably small headers and reports the margin', () => {
    const v = evaluateBudget(fakeObs({ headerBytes: 1200 }), P);
    expect(v.outcome).toBe('pass');
    expect(v.observed).toContain('2896 bytes below 4096');
  });
  it('fails at the warning level with the instance severity', () => {
    const v = evaluateBudget(fakeObs({ headerBytes: 3974 }), P);
    expect(v.outcome).toBe('fail');
    expect(v.severity).toBeUndefined();
    expect(v.observed).toContain('within 122 bytes');
  });
  it('escalates to high at or over the proxy buffer size', () => {
    expect(evaluateBudget(fakeObs({ headerBytes: 4200 }), P)).toMatchObject({ outcome: 'fail', severity: 'high' });
  });
  it('requires warn_bytes below high_bytes', () => {
    expect(headerBudgetParams.safeParse({ warn_bytes: 5000, high_bytes: 4096 }).success).toBe(false);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/checks/types/http-cookie.test.ts test/checks/types/header-budget.test.ts`
Expected: FAIL, because the modules can't be resolved.

- [ ] **Step 3: Implement both types**

`src/checks/types/http-cookie.ts`:
```ts
import { z } from 'zod';
import type { HttpObservation } from '../../net/http.js';
import type { CheckType } from '../check-type.js';
import { getPage } from '../context.js';

export const httpCookieParams = z.object({
  require: z.array(z.enum(['secure', 'httponly', 'samesite'])).min(1).default(['secure', 'httponly', 'samesite']),
});
export type HttpCookieParams = z.infer<typeof httpCookieParams>;

export function evaluateCookies(obs: HttpObservation, p: HttpCookieParams): { outcome: 'pass' | 'fail'; observed: string } {
  if (obs.setCookies.length === 0) return { outcome: 'pass', observed: 'no cookies set on this response' };
  const problems: string[] = [];
  for (const cookie of obs.setCookies) {
    const missing = p.require.filter((flag) => !cookie.attributes.some((a) => a === flag || a.startsWith(`${flag}=`)));
    if (missing.length > 0) problems.push(`${cookie.name} missing ${missing.join(', ')}`);
  }
  if (problems.length > 0) return { outcome: 'fail', observed: problems.join('; ') };
  return { outcome: 'pass', observed: `${obs.setCookies.length} cookie(s) set, all with ${p.require.join(', ')}` };
}

export const httpCookieCheck: CheckType<HttpCookieParams> = {
  type: 'http_cookie',
  supports: ['web', 'api'],
  params: httpCookieParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'target') throw new Error('http_cookie runs on targets only');
    const page = await getPage(ctx, subject);
    return { ...evaluateCookies(page.obs, p), evidence_id: page.evidenceId };
  },
};
```

`src/checks/types/header-budget.ts`:
```ts
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
```

- [ ] **Step 4: Register both types**

In `src/checks/registry.ts`, add the imports and extend `ALL`:
```ts
import type { AnyCheckType } from './check-type.js';
import { headerBudgetCheck } from './types/header-budget.js';
import { httpCookieCheck } from './types/http-cookie.js';
import { httpHeaderCheck } from './types/http-header.js';
import { httpRedirectCheck } from './types/http-redirect.js';

/** Every check type the engine knows. Learning may add YAML instances of these types, never new types. */
const ALL: AnyCheckType[] = [httpRedirectCheck, httpHeaderCheck, httpCookieCheck, headerBudgetCheck];

export const CHECK_TYPES: ReadonlyMap<string, AnyCheckType> = new Map(ALL.map((t) => [t.type, t]));
```

- [ ] **Step 5: Write the seed instances**

`knowledge/checks/cookie-flags.yaml`:
```yaml
id: cookie-flags
type: http_cookie
title: Cookies set Secure, HttpOnly and SameSite
severity: medium
applies_to: [web, api]
params:
  require: [secure, httponly, samesite]
fix_hints:
  nginx: 'proxy_cookie_flags ~ secure httponly samesite=lax;  (nginx 1.19.3+)'
  express: "express-session / res.cookie(name, value, { secure: true, httpOnly: true, sameSite: 'lax' })"
  nestjs: "res.cookie(name, value, { secure: true, httpOnly: true, sameSite: 'lax' })"
  nextjs: "cookies().set(name, value, { secure: true, httpOnly: true, sameSite: 'lax' })"
  any: 'Cookies that client-side JS must read (e.g. CSRF tokens) may skip HttpOnly; document that as an accepted exception.'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/header-budget.yaml`:
```yaml
id: header-budget
type: header_budget
title: Response headers stay well below proxy buffer limits
severity: medium
applies_to: [web, api]
params:
  warn_bytes: 3072
  high_bytes: 4096
fix_hints:
  nginx: 'proxy_buffer_size 16k; proxy_buffers 8 16k; proxy_busy_buffers_size 32k;'
  any: 'Also shrink what the app sends: large session cookies (tokens embedding profile data or photos) and long CSP strings.'
source_url: https://nginx.org/en/docs/http/ngx_http_proxy_module.html#proxy_buffer_size
added_by: seed
review: approved
```

- [ ] **Step 6: Run tests and typecheck**

Run: `npx vitest run test/checks && npx tsc -p tsconfig.json`
Expected: all tests PASS (the seed catalog now has 11 instances); `tsc` exits 0.

- [ ] **Step 7: Commit**

```bash
git add src/checks/types/http-cookie.ts src/checks/types/header-budget.ts src/checks/registry.ts knowledge/checks/cookie-flags.yaml knowledge/checks/header-budget.yaml test/checks/types/http-cookie.test.ts test/checks/types/header-budget.test.ts
git commit -m "feat(checks): add cookie flag and header budget checks"
```

---

### Task 12: `exposed_path` check type (SPA-safe)

**Files:**
- Create: `src/checks/types/exposed-path.ts`, `knowledge/checks/exposed-paths.yaml`
- Modify: `src/checks/registry.ts`
- Test: `test/checks/types/exposed-path.test.ts`

**Interfaces:**
- Consumes: `CheckType` (Task 9); `getPage` (Task 8); `HttpObservation` (Task 6); `SEVERITIES`, `maxSeverity`, `Severity` (Task 1)
- Produces:
  - `exposedPathParams`, `isExposed(obs, baseline, signature: RegExp): boolean`
  - `scriptSources(html, pageUrl): string[]`
  - `exposedPathCheck`

- [ ] **Step 1: Write the failing tests**

`test/checks/types/exposed-path.test.ts`:
```ts
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { exposedPathCheck, exposedPathParams, isExposed, scriptSources } from '../../../src/checks/types/exposed-path.js';
import { fakeObs, makeCtx, targetSubject } from '../../helpers/ctx.js';

const ENV_SIGNATURE = /^[A-Z][A-Z0-9_]*\s*=/m;

describe('isExposed', () => {
  const baseline = fakeObs({ status: 200, bodySnippet: '<html>app shell</html>' });
  it('ignores the SPA fallback page', () => {
    expect(isExposed(fakeObs({ status: 200, bodySnippet: '<html>app shell</html>' }), baseline, ENV_SIGNATURE)).toBe(false);
  });
  it('requires a 200', () => {
    expect(isExposed(fakeObs({ status: 404, bodySnippet: 'DB_PASSWORD=x' }), baseline, ENV_SIGNATURE)).toBe(false);
  });
  it('requires the content signature', () => {
    expect(isExposed(fakeObs({ status: 200, bodySnippet: 'hello' }), baseline, ENV_SIGNATURE)).toBe(false);
  });
  it('flags a real .env file', () => {
    expect(isExposed(fakeObs({ status: 200, bodySnippet: 'DB_PASSWORD=x\n' }), baseline, ENV_SIGNATURE)).toBe(true);
  });
});

describe('scriptSources', () => {
  it('resolves relative script URLs and drops duplicates', () => {
    const html = '<script src="/main.js"></script><script type="module" src="chunk.js?v=1"></script><script src="/main.js"></script>';
    expect(scriptSources(html, 'https://app.example.com/a/')).toEqual([
      'https://app.example.com/main.js',
      'https://app.example.com/a/chunk.js?v=1',
    ]);
  });
});

describe('exposed_path check', () => {
  it('reports exposed files and source maps, skips SPA fallbacks, and stores no file contents', async () => {
    const pages: Record<string, { status: number; body: string }> = {
      '/': { status: 200, body: '<html><script src="/main.js"></script></html>' },
      '/.env': { status: 200, body: 'DB_PASSWORD=supersecret\n' },
      '/main.js.map': { status: 200, body: '{"version":3,"mappings":"AAAA"}' },
    };
    const { ctx, dir } = await makeCtx({
      http: async (url) => {
        const page = pages[new URL(url).pathname] ?? { status: 200, body: '<html>shell</html>' };
        return fakeObs({ url, status: page.status, bodySnippet: page.body });
      },
    });
    const params = exposedPathParams.parse({
      paths: [
        { path: '/.env', signature: '^[A-Z][A-Z0-9_]*\\s*=', severity: 'critical' },
        { path: '/.git/config', signature: '^\\[core\\]', severity: 'high' },
      ],
    });
    const out = await exposedPathCheck.run(ctx, targetSubject(ctx), params, {} as never);
    expect(out.outcome).toBe('fail');
    expect(out.severity).toBe('critical');
    expect(out.observed).toContain('/.env');
    expect(out.observed).toContain('/main.js.map');
    expect(out.observed).not.toContain('/.git/config');
    const evidence = readFileSync(path.join(dir, '.secagent', 'evidence', `${out.evidence_id}.json`), 'utf8');
    expect(evidence).not.toContain('supersecret');
  });

  it('rejects an invalid signature regex', () => {
    expect(exposedPathParams.safeParse({ paths: [{ path: '/.env', signature: '([', severity: 'high' }] }).success).toBe(false);
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/checks/types/exposed-path.test.ts`
Expected: FAIL, because the module can't be resolved.

- [ ] **Step 3: Implement `src/checks/types/exposed-path.ts`**

```ts
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import type { HttpObservation } from '../../net/http.js';
import { maxSeverity, SEVERITIES, type Severity } from '../../types.js';
import type { CheckType } from '../check-type.js';
import { getPage } from '../context.js';

const Regex = z.string().refine(
  (s) => {
    try {
      new RegExp(s);
      return true;
    } catch {
      return false;
    }
  },
  { message: 'invalid regular expression' },
);

export const exposedPathParams = z.object({
  paths: z
    .array(z.object({ path: z.string().startsWith('/'), signature: Regex, severity: z.enum(SEVERITIES) }))
    .min(1),
  source_maps: z
    .object({
      enabled: z.boolean().default(true),
      max_scripts: z.number().int().min(0).max(20).default(5),
      severity: z.enum(SEVERITIES).default('low'),
    })
    .prefault({}),
});
export type ExposedPathParams = z.infer<typeof exposedPathParams>;

const SOURCE_MAP_SIGNATURE = /"mappings"\s*:/;

/** Exposed = 200, different from the random-path baseline (SPA fallback), and matching the file's signature. */
export function isExposed(obs: HttpObservation, baseline: HttpObservation, signature: RegExp): boolean {
  if (obs.status !== 200) return false;
  if (baseline.status === 200 && obs.bodySnippet === baseline.bodySnippet) return false;
  return signature.test(obs.bodySnippet);
}

export function scriptSources(html: string, pageUrl: string): string[] {
  const found: string[] = [];
  for (const match of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+\.js(?:\?[^"']*)?)["']/gi)) {
    const src = match[1];
    if (!src) continue;
    try {
      found.push(new URL(src, pageUrl).href);
    } catch {
      // Unparseable src attributes are skipped.
    }
  }
  return [...new Set(found)];
}

interface Hit {
  path: string;
  severity: Severity;
  status: number;
}

export const exposedPathCheck: CheckType<ExposedPathParams> = {
  type: 'exposed_path',
  supports: ['web', 'api'],
  params: exposedPathParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'target') throw new Error('exposed_path runs on targets only');
    const origin = new URL(subject.target.url).origin;
    const baselineUrl = `${origin}/secagent-baseline-${randomBytes(6).toString('hex')}`;
    const baseline = await ctx.net.http(baselineUrl);
    const checked: Array<{ path: string; status: number }> = [];
    const hits: Hit[] = [];

    for (const entry of p.paths) {
      const obs = await ctx.net.http(`${origin}${entry.path}`);
      checked.push({ path: entry.path, status: obs.status });
      if (isExposed(obs, baseline, new RegExp(entry.signature, 'm'))) hits.push({ path: entry.path, severity: entry.severity, status: obs.status });
    }

    if (p.source_maps.enabled && p.source_maps.max_scripts > 0) {
      const page = await getPage(ctx, subject);
      const scripts = scriptSources(page.obs.bodySnippet, page.obs.url)
        .filter((src) => new URL(src).origin === origin)
        .slice(0, p.source_maps.max_scripts);
      for (const src of scripts) {
        const mapUrl = new URL(src);
        mapUrl.search = '';
        mapUrl.pathname = `${mapUrl.pathname}.map`;
        const obs = await ctx.net.http(mapUrl.href);
        checked.push({ path: mapUrl.pathname, status: obs.status });
        if (isExposed(obs, baseline, SOURCE_MAP_SIGNATURE)) hits.push({ path: mapUrl.pathname, severity: p.source_maps.severity, status: obs.status });
      }
    }

    // Statuses and paths only: never persist the contents of an exposed file.
    const evidence_id = await ctx.evidence.put('http', subject.target.id, `exposed-path probe of ${checked.length} path(s)`, {
      baseline: { url: baselineUrl, status: baseline.status, bodyBytes: baseline.bodyBytes },
      checked,
      hits,
    });
    if (hits.length === 0) {
      return {
        outcome: 'pass',
        observed: `none of ${checked.length} sensitive path(s) served (SPA fallback ruled out against a random-path baseline)`,
        evidence_id,
      };
    }
    return {
      outcome: 'fail',
      severity: maxSeverity(hits.map((h) => h.severity)),
      observed: `served: ${hits.map((h) => h.path).join(', ')}`,
      evidence_id,
      details: { hits },
    };
  },
};
```

- [ ] **Step 4: Register the type**

In `src/checks/registry.ts`, add `import { exposedPathCheck } from './types/exposed-path.js';` and set:
```ts
const ALL: AnyCheckType[] = [httpRedirectCheck, httpHeaderCheck, httpCookieCheck, headerBudgetCheck, exposedPathCheck];
```

- [ ] **Step 5: Write the seed instance `knowledge/checks/exposed-paths.yaml`**

```yaml
id: exposed-paths
type: exposed_path
title: Secrets, repository metadata and source maps are not served
severity: high
applies_to: [web, api]
params:
  paths:
    - { path: /.env, signature: '^[A-Z][A-Z0-9_]*\s*=', severity: critical }
    - { path: /.git/config, signature: '^\[core\]', severity: high }
    - { path: /.git/HEAD, signature: '^ref: refs/', severity: high }
    - { path: /.aws/credentials, signature: '^\[default\]', severity: critical }
    - { path: /.DS_Store, signature: 'Bud1', severity: low }
  source_maps:
    enabled: true
    max_scripts: 5
    severity: low
fix_hints:
  nginx: 'location ~ /\.(?!well-known) { deny all; }   location ~ \.map$ { deny all; }'
  angular: '"sourceMap": false in the production configuration of angular.json'
  vue: 'build.sourcemap: false in vite.config'
  nextjs: 'productionBrowserSourceMaps: false (the default) in next.config'
  any: 'Remove secrets and VCS metadata from the deployed artifact; keep .env out of the web root and the image.'
source_url: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/02-Configuration_and_Deployment_Management_Testing/04-Review_Old_Backup_and_Unreferenced_Files_for_Sensitive_Information
added_by: seed
review: approved
```

- [ ] **Step 6: Run tests and typecheck**

Run: `npx vitest run test/checks && npx tsc -p tsconfig.json`
Expected: all tests PASS (the seed catalog now has 12 instances); `tsc` exits 0.

- [ ] **Step 7: Commit**

```bash
git add src/checks/types/exposed-path.ts src/checks/registry.ts knowledge/checks/exposed-paths.yaml test/checks/types/exposed-path.test.ts
git commit -m "feat(checks): add SPA-safe exposed file and source map check"
```

---

### Task 13: `tls` check type

**Files:**
- Create: `src/checks/types/tls.ts`, `knowledge/checks/tls-no-legacy.yaml`, `knowledge/checks/tls-modern.yaml`, `knowledge/checks/tls-cert-valid.yaml`
- Modify: `src/checks/registry.ts`
- Test: `test/checks/types/tls.test.ts`

**Interfaces:**
- Consumes:
  - `CheckType` (Task 9); `memoize`, `CheckContext` (Task 8)
  - `NetClient`, `ScopedNet` (Task 8)
  - `NetError` (Task 5); `isHandshakeRejection`, `LEGACY_CIPHERS`, `NON_AEAD_TLS12_CIPHERS`, `TlsObservation` (Task 7)
  - `Scope` (Task 5); `EvidenceStore` (Task 8); `startTls` (Task 6)
- Produces:
  - `tlsParams`, `interface LegacyAttempt`
  - `evaluateLegacy(attempts)`, `evaluateModern(defaultObs, weak)`, `evaluateCert(obs, minDays, now)`
  - `tlsCheck`

- [ ] **Step 1: Write the failing tests**

`test/checks/types/tls.test.ts`:
```ts
import { afterEach, describe, expect, it } from 'vitest';
import type { CheckContext } from '../../../src/checks/context.js';
import { evaluateCert, evaluateLegacy, evaluateModern, tlsCheck, tlsParams } from '../../../src/checks/types/tls.js';
import { EvidenceStore } from '../../../src/evidence/store.js';
import { ScopedNet } from '../../../src/net/scoped.js';
import { LEGACY_CIPHERS, type TlsObservation } from '../../../src/net/tls.js';
import { validateProject } from '../../../src/project/schema.js';
import { Scope } from '../../../src/project/scope.js';
import { startTls, type Running } from '../../helpers/servers.js';
import { tempDir } from '../../helpers/tmp.js';

const STRICT_CIPHERS =
  'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';

const obs = (partial: Partial<TlsObservation>): TlsObservation => ({
  host: 'app.example.com',
  port: 443,
  protocol: 'TLSv1.3',
  cipher: 'TLS_AES_256_GCM_SHA384',
  authorized: true,
  ...partial,
});
const cert = { subject: 'CN=app', issuer: 'CN=ca', valid_from: 'Jan  1 00:00:00 2026 GMT', days_remaining: 0, hostname_ok: true };

describe('evaluateLegacy', () => {
  it('fails when either legacy protocol is accepted', () => {
    const v = evaluateLegacy([
      { version: 'TLSv1', accepted: true, cipher: 'ECDHE-RSA-AES256-SHA' },
      { version: 'TLSv1.1', accepted: false, code: 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION' },
    ]);
    expect(v).toEqual({ outcome: 'fail', observed: 'server accepts TLSv1 (ECDHE-RSA-AES256-SHA)' });
  });
  it('passes when both are refused', () => {
    const v = evaluateLegacy([
      { version: 'TLSv1', accepted: false, code: 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION' },
      { version: 'TLSv1.1', accepted: false, code: 'ERR_SSL_TLSV1_ALERT_PROTOCOL_VERSION' },
    ]);
    expect(v.outcome).toBe('pass');
  });
});

describe('evaluateModern', () => {
  it('passes TLS 1.3 with weak TLS 1.2 refused', () => {
    expect(evaluateModern(obs({}), { accepted: false, code: 'ERR_SSL_SSL/TLS_ALERT_HANDSHAKE_FAILURE' }).outcome).toBe('pass');
  });
  it('fails a CBC default handshake', () => {
    expect(evaluateModern(obs({ protocol: 'TLSv1.2', cipher: 'ECDHE-RSA-AES256-SHA384' }), { accepted: true }).outcome).toBe('fail');
  });
  it('fails when weak TLS 1.2 ciphers are also accepted', () => {
    const v = evaluateModern(obs({}), { accepted: true, cipher: 'ECDHE-RSA-AES256-SHA384' });
    expect(v.observed).toContain('non-AEAD');
  });
});

describe('evaluateCert', () => {
  const now = new Date('2026-10-28T00:00:00Z');
  it('passes a trusted, matching certificate with time left', () => {
    expect(evaluateCert(obs({ cert: { ...cert, valid_to: 'Jan 26 00:00:00 2027 GMT' } }), 21, now).outcome).toBe('pass');
  });
  it('fails one expiring inside the renewal window', () => {
    expect(evaluateCert(obs({ cert: { ...cert, valid_to: 'Nov  7 00:00:00 2026 GMT' } }), 21, now).observed).toContain('expires in 10 day(s)');
  });
  it('fails an expired, untrusted, mismatched certificate with every reason', () => {
    const v = evaluateCert(
      obs({ authorized: false, authorization_error: 'CERT_HAS_EXPIRED', cert: { ...cert, valid_to: 'Sep 16 00:00:00 2026 GMT', hostname_ok: false, hostname_error: 'mismatch' } }),
      21,
      now,
    );
    expect(v.observed).toContain('not trusted (CERT_HAS_EXPIRED)');
    expect(v.observed).toContain('does not match the hostname');
    expect(v.observed).toContain('expired 42 day(s) ago');
  });
});

describe('tls check against real servers', () => {
  const running: Running[] = [];
  afterEach(async () => {
    await Promise.all(running.splice(0).map((s) => s.close()));
  });

  async function setup(serverOpts: Parameters<typeof startTls>[0]) {
    const s = await startTls(serverOpts);
    running.push(s);
    const project = validateProject({ version: 1, name: 't', targets: [{ id: 'app', url: `https://127.0.0.1:${s.port}`, type: 'web', env: 'test' }] });
    const ctx: CheckContext = {
      project,
      net: new ScopedNet(new Scope(project), 4),
      evidence: new EvidenceStore(await tempDir(), 'test'),
      now: () => new Date(),
      memo: new Map(),
    };
    const target = project.targets[0];
    if (!target) throw new Error('no target');
    return { ctx, subject: { kind: 'target' as const, target } };
  }
  const run = (ctx: CheckContext, subject: Awaited<ReturnType<typeof setup>>['subject'], assert: string) =>
    tlsCheck.run(ctx, subject, tlsParams.parse({ assert }), {} as never);

  it('fails no_legacy on a server accepting TLS 1.0', async () => {
    const { ctx, subject } = await setup({ minVersion: 'TLSv1', ciphers: LEGACY_CIPHERS });
    const out = await run(ctx, subject, 'no_legacy');
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('TLSv1');
  });

  it('passes no_legacy and modern on a strict server', async () => {
    const { ctx, subject } = await setup({ minVersion: 'TLSv1.2', ciphers: STRICT_CIPHERS });
    expect((await run(ctx, subject, 'no_legacy')).outcome).toBe('pass');
    expect((await run(ctx, subject, 'modern')).outcome).toBe('pass');
  });

  it('fails modern when weak TLS 1.2 ciphers are accepted', async () => {
    const { ctx, subject } = await setup({ minVersion: 'TLSv1.2', ciphers: 'DEFAULT:@SECLEVEL=0' });
    expect((await run(ctx, subject, 'modern')).observed).toContain('non-AEAD');
  });

  it('fails cert on a self-signed certificate', async () => {
    const { ctx, subject } = await setup({ minVersion: 'TLSv1.2' });
    expect((await run(ctx, subject, 'cert')).observed).toContain('not trusted');
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/checks/types/tls.test.ts`
Expected: FAIL, because `../../../src/checks/types/tls.js` can't be resolved.

- [ ] **Step 3: Implement `src/checks/types/tls.ts`**

```ts
import type { SecureVersion } from 'node:tls';
import { z } from 'zod';
import { NetError } from '../../net/errors.js';
import { stripBrackets } from '../../net/ip.js';
import type { NetClient } from '../../net/scoped.js';
import { isHandshakeRejection, LEGACY_CIPHERS, NON_AEAD_TLS12_CIPHERS, type TlsObservation } from '../../net/tls.js';
import type { CheckType } from '../check-type.js';
import { memoize } from '../context.js';

export const tlsParams = z.object({
  assert: z.enum(['no_legacy', 'modern', 'cert']),
  port: z.number().int().min(1).max(65535).optional(),
  min_cert_days: z.number().int().nonnegative().default(21),
});
export type TlsParams = z.infer<typeof tlsParams>;

type Verdict = { outcome: 'pass' | 'fail'; observed: string };

export interface LegacyAttempt {
  version: SecureVersion;
  accepted: boolean;
  cipher?: string | null;
  code?: string;
}

export function evaluateLegacy(attempts: readonly LegacyAttempt[]): Verdict {
  const accepted = attempts.filter((a) => a.accepted);
  if (accepted.length > 0) {
    return { outcome: 'fail', observed: `server accepts ${accepted.map((a) => `${a.version}${a.cipher ? ` (${a.cipher})` : ''}`).join(' and ')}` };
  }
  const codes = [...new Set(attempts.map((a) => a.code).filter(Boolean))].join(', ');
  return { outcome: 'pass', observed: `${attempts.map((a) => a.version).join(' and ')} refused (${codes})` };
}

const AEAD = /GCM|CHACHA20|CCM/i;

export function evaluateModern(def: TlsObservation, weak: { accepted: boolean; cipher?: string | null; code?: string }): Verdict {
  const negotiated = `${def.protocol ?? 'unknown protocol'} with ${def.cipher ?? 'unknown cipher'}`;
  const modernDefault = def.protocol === 'TLSv1.3' || (def.protocol === 'TLSv1.2' && AEAD.test(def.cipher ?? ''));
  if (!modernDefault) {
    return { outcome: 'fail', observed: `default handshake negotiated ${negotiated}; expected TLS 1.3, or TLS 1.2 with an AEAD (GCM/CHACHA20) cipher` };
  }
  if (weak.accepted) {
    return { outcome: 'fail', observed: `default handshake is ${negotiated}, but the server also accepts the non-AEAD TLS 1.2 cipher ${weak.cipher ?? 'unknown'}` };
  }
  return { outcome: 'pass', observed: `default handshake ${negotiated}; non-AEAD TLS 1.2 ciphers refused` };
}

export function evaluateCert(obs: TlsObservation, minDays: number, now: Date): Verdict {
  const cert = obs.cert;
  if (!cert) return { outcome: 'fail', observed: 'server presented no certificate' };
  const days = Math.floor((Date.parse(cert.valid_to) - now.getTime()) / 86_400_000);
  const problems: string[] = [];
  if (!obs.authorized) problems.push(`not trusted (${obs.authorization_error ?? 'unknown reason'})`);
  if (!cert.hostname_ok) problems.push(`does not match the hostname (${cert.hostname_error ?? 'mismatch'})`);
  if (days < 0) problems.push(`expired ${-days} day(s) ago (${cert.valid_to})`);
  else if (days < minDays) problems.push(`expires in ${days} day(s) (${cert.valid_to}); renew at least ${minDays} days ahead`);
  if (problems.length > 0) return { outcome: 'fail', observed: `certificate ${problems.join('; ')}` };
  return { outcome: 'pass', observed: `certificate trusted, matches hostname, ${days} days left (until ${cert.valid_to})` };
}

async function attempt(
  net: NetClient,
  host: string,
  port: number,
  opts: { minVersion: SecureVersion; maxVersion: SecureVersion; ciphers: string },
): Promise<{ accepted: boolean; cipher?: string | null; code?: string }> {
  try {
    const result = await net.tls(host, port, opts);
    return { accepted: true, cipher: result.cipher };
  } catch (e) {
    if (e instanceof NetError && isHandshakeRejection(e.code)) return { accepted: false, code: e.code };
    throw e;
  }
}

export const tlsCheck: CheckType<TlsParams> = {
  type: 'tls',
  supports: ['web', 'api'],
  params: tlsParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'target') throw new Error('tls runs on targets only');
    const url = new URL(subject.target.url);
    const host = stripBrackets(url.hostname);
    const port = p.port ?? (url.port ? Number(url.port) : 443);
    const id = subject.target.id;

    if (p.assert === 'no_legacy') {
      const attempts: LegacyAttempt[] = [];
      for (const version of ['TLSv1', 'TLSv1.1'] as const) {
        attempts.push({ version, ...(await attempt(ctx.net, host, port, { minVersion: version, maxVersion: version, ciphers: LEGACY_CIPHERS })) });
      }
      const evidence_id = await ctx.evidence.put('tls', id, `legacy protocol probe ${host}:${port}`, { host, port, attempts });
      return { ...evaluateLegacy(attempts), evidence_id };
    }

    const def = await memoize(ctx, `TLS ${host}:${port}`, () => ctx.net.tls(host, port));
    if (p.assert === 'modern') {
      const weak = await attempt(ctx.net, host, port, { minVersion: 'TLSv1.2', maxVersion: 'TLSv1.2', ciphers: NON_AEAD_TLS12_CIPHERS });
      const evidence_id = await ctx.evidence.put('tls', id, `cipher probe ${host}:${port}`, { default: def, weak_tls12_probe: weak });
      return { ...evaluateModern(def, weak), evidence_id };
    }
    const evidence_id = await ctx.evidence.put('tls', id, `certificate ${host}:${port}`, def);
    return { ...evaluateCert(def, p.min_cert_days, ctx.now()), evidence_id };
  },
};
```

- [ ] **Step 4: Register the type**

In `src/checks/registry.ts`, add `import { tlsCheck } from './types/tls.js';` and set:
```ts
const ALL: AnyCheckType[] = [httpRedirectCheck, httpHeaderCheck, httpCookieCheck, headerBudgetCheck, exposedPathCheck, tlsCheck];
```

- [ ] **Step 5: Write the seed instances**

`knowledge/checks/tls-no-legacy.yaml`:
```yaml
id: tls-no-legacy
type: tls
title: TLS 1.0 and 1.1 are refused
severity: high
applies_to: [web, api]
params:
  assert: no_legacy
fix_hints:
  nginx: 'ssl_protocols TLSv1.2 TLSv1.3;'
  any: 'On an AWS ALB/NLB, use a TLS 1.2+ security policy such as ELBSecurityPolicy-TLS13-1-2-2021-06. On CDNs, set the minimum TLS version to 1.2.'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/tls-modern.yaml`:
```yaml
id: tls-modern
type: tls
title: Only modern (AEAD) cipher suites are accepted
severity: medium
applies_to: [web, api]
params:
  assert: modern
fix_hints:
  nginx: 'ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305; ssl_prefer_server_ciphers off;'
  any: 'Load balancers/CDNs: choose a security policy that excludes CBC (SHA1/SHA256/SHA384 non-GCM) suites.'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
added_by: seed
review: approved
```

`knowledge/checks/tls-cert-valid.yaml`:
```yaml
id: tls-cert-valid
type: tls
title: Certificate is trusted, matches the hostname and has at least 21 days left
severity: high
applies_to: [web, api]
params:
  assert: cert
  min_cert_days: 21
fix_hints:
  any: 'Renew and automate renewal (certbot, ACM). Check every listener, including vhosts reached by direct IP, not only the main domain.'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Security_Cheat_Sheet.html
added_by: seed
review: approved
```

- [ ] **Step 6: Run tests and typecheck**

Run: `npx vitest run test/checks && npx tsc -p tsconfig.json`
Expected: all tests PASS (the seed catalog now has 15 instances); `tsc` exits 0.

- [ ] **Step 7: Commit**

```bash
git add src/checks/types/tls.ts src/checks/registry.ts knowledge/checks/tls-no-legacy.yaml knowledge/checks/tls-modern.yaml knowledge/checks/tls-cert-valid.yaml test/checks/types/tls.test.ts
git commit -m "feat(checks): add TLS protocol, cipher and certificate checks"
```

---

### Task 14: `port_exposure` check type

**Files:**
- Create: `src/util/pool.ts`, `src/checks/types/port-exposure.ts`, `knowledge/checks/ports-exposed.yaml`
- Modify: `src/checks/registry.ts`
- Test: `test/util/pool.test.ts`, `test/checks/types/port-exposure.test.ts`

**Interfaces:**
- Consumes: `CheckType` (Task 9); `subjectHostname`, `subjectId` (Task 8); `PortState` (Task 7); `SEVERITIES`, `maxSeverity`, `Severity` (Task 1); test helpers (Task 8)
- Produces:
  - `mapLimit(items, limit, fn): Promise<R[]>`
  - `portExposureParams`, `evaluatePorts(params, states: Map<number, PortState>, scanLabel)`
  - `portExposureCheck`

- [ ] **Step 1: Write the failing tests**

`test/util/pool.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { mapLimit } from '../../src/util/pool.js';

describe('mapLimit', () => {
  it('keeps order and never exceeds the limit', async () => {
    let active = 0;
    let peak = 0;
    const out = await mapLimit([1, 2, 3, 4, 5, 6], 2, async (n) => {
      active += 1;
      peak = Math.max(peak, active);
      await new Promise((r) => setTimeout(r, 5));
      active -= 1;
      return n * 10;
    });
    expect(out).toEqual([10, 20, 30, 40, 50, 60]);
    expect(peak).toBe(2);
  });
});
```

`test/checks/types/port-exposure.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { evaluatePorts, portExposureCheck, portExposureParams } from '../../../src/checks/types/port-exposure.js';
import type { PortState } from '../../../src/net/tcp.js';
import { hostSubject, makeCtx } from '../../helpers/ctx.js';

const P = portExposureParams.parse({
  ports: [
    { port: 22, service: 'ssh', severity: 'medium' },
    { port: 5432, service: 'postgres', severity: 'high' },
  ],
});
const states = (entries: Array<[number, PortState]>) => new Map(entries);

describe('evaluatePorts', () => {
  it('fails open sensitive ports with the highest port severity', () => {
    const v = evaluatePorts(P, states([[22, 'open'], [5432, 'open'], [80, 'open'], [443, 'open']]), 'office');
    expect(v).toEqual({ outcome: 'fail', severity: 'high', observed: 'open from network "office": 22/ssh, 5432/postgres' });
  });
  it('passes when sensitive ports are filtered but the host answers on a liveness port', () => {
    expect(evaluatePorts(P, states([[22, 'timeout'], [5432, 'timeout'], [80, 'timeout'], [443, 'open']]), 'home').outcome).toBe('pass');
  });
  it('passes when a sensitive port is refused', () => {
    expect(evaluatePorts(P, states([[22, 'closed'], [5432, 'timeout'], [80, 'timeout'], [443, 'timeout']]), 'home').outcome).toBe('pass');
  });
  it('is unverifiable when nothing answers at all', () => {
    const v = evaluatePorts(P, states([[22, 'timeout'], [5432, 'timeout'], [80, 'timeout'], [443, 'timeout']]), 'home');
    expect(v.outcome).toBe('unverifiable');
    expect(v.observed).toContain('proves nothing');
  });
});

describe('port_exposure check', () => {
  it('probes the host address and stores every port state as evidence', async () => {
    const probed: string[] = [];
    const { ctx } = await makeCtx({
      tcp: async (host, port) => {
        probed.push(`${host}:${port}`);
        return port === 22 ? 'open' : 'closed';
      },
    });
    const out = await portExposureCheck.run(ctx, hostSubject(ctx), P, {} as never);
    expect(probed.sort()).toEqual(['203.0.113.10:22', '203.0.113.10:443', '203.0.113.10:5432', '203.0.113.10:80']);
    expect(out).toMatchObject({ outcome: 'fail', severity: 'medium' });
    expect(out.observed).toContain('test-net');
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/util/pool.test.ts test/checks/types/port-exposure.test.ts`
Expected: FAIL, because the modules can't be resolved.

- [ ] **Step 3: Implement `src/util/pool.ts` and `src/checks/types/port-exposure.ts`**

`src/util/pool.ts`:
```ts
/** Maps items with at most `limit` promises in flight, preserving input order. */
export async function mapLimit<T, R>(items: readonly T[], limit: number, fn: (item: T) => Promise<R>): Promise<R[]> {
  const results = new Array<R>(items.length);
  let next = 0;
  async function worker(): Promise<void> {
    while (next < items.length) {
      const index = next;
      next += 1;
      results[index] = await fn(items[index] as T);
    }
  }
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, () => worker()));
  return results;
}
```

`src/checks/types/port-exposure.ts`:
```ts
import { z } from 'zod';
import type { PortState } from '../../net/tcp.js';
import { maxSeverity, SEVERITIES, type Severity } from '../../types.js';
import { mapLimit } from '../../util/pool.js';
import type { CheckType } from '../check-type.js';
import { subjectHostname, subjectId } from '../context.js';

const Port = z.number().int().min(1).max(65535);

export const portExposureParams = z.object({
  ports: z.array(z.object({ port: Port, service: z.string().min(1), severity: z.enum(SEVERITIES) })).min(1),
  /** Ports whose answer (open or refused) proves the host is reachable from this network. */
  liveness_ports: z.array(Port).default([80, 443]),
  concurrency: z.number().int().min(1).max(4).default(4),
});
export type PortExposureParams = z.infer<typeof portExposureParams>;

export function evaluatePorts(
  p: PortExposureParams,
  states: ReadonlyMap<number, PortState>,
  scanLabel: string,
): { outcome: 'pass' | 'fail' | 'unverifiable'; observed: string; severity?: Severity } {
  const open = p.ports.filter((x) => states.get(x.port) === 'open');
  if (open.length > 0) {
    return {
      outcome: 'fail',
      severity: maxSeverity(open.map((o) => o.severity)),
      observed: `open from network "${scanLabel}": ${open.map((o) => `${o.port}/${o.service}`).join(', ')}`,
    };
  }
  const anyRefused = p.ports.some((x) => states.get(x.port) === 'closed');
  const alive = p.liveness_ports.some((lp) => states.get(lp) === 'open' || states.get(lp) === 'closed');
  if (anyRefused || alive) {
    return { outcome: 'pass', observed: `none of ${p.ports.length} sensitive ports open from network "${scanLabel}" (refused or filtered)` };
  }
  return {
    outcome: 'unverifiable',
    observed: `no response on any probed port (including ${p.liveness_ports.join('/')}) from network "${scanLabel}"; the host may only accept allowlisted networks, so this proves nothing`,
  };
}

export const portExposureCheck: CheckType<PortExposureParams> = {
  type: 'port_exposure',
  supports: ['web', 'api', 'host'],
  params: portExposureParams,
  async run(ctx, subject, p) {
    const host = subjectHostname(subject);
    const ports = [...new Set([...p.ports.map((x) => x.port), ...p.liveness_ports])];
    const probed = await mapLimit(ports, p.concurrency, async (port) => [port, await ctx.net.tcp(host, port)] as const);
    const states = new Map<number, PortState>(probed);
    const evidence_id = await ctx.evidence.put('tcp', subjectId(subject), `TCP connect probe of ${ports.length} ports on ${host}`, {
      host,
      states: Object.fromEntries(states),
    });
    return { ...evaluatePorts(p, states, ctx.project.network.scan_label), evidence_id };
  },
};
```

- [ ] **Step 4: Register the type**

In `src/checks/registry.ts`, add `import { portExposureCheck } from './types/port-exposure.js';` and set:
```ts
const ALL: AnyCheckType[] = [
  httpRedirectCheck,
  httpHeaderCheck,
  httpCookieCheck,
  headerBudgetCheck,
  exposedPathCheck,
  tlsCheck,
  portExposureCheck,
];
```

- [ ] **Step 5: Write the seed instance `knowledge/checks/ports-exposed.yaml`**

It applies to listed hosts only, so CDNs and shared infrastructure behind target hostnames are never port-probed.
```yaml
id: ports-exposed
type: port_exposure
title: Admin and database ports are not reachable from this network
severity: high
applies_to: [host]
params:
  ports:
    - { port: 21, service: ftp, severity: medium }
    - { port: 22, service: ssh, severity: medium }
    - { port: 23, service: telnet, severity: high }
    - { port: 2375, service: docker-api, severity: critical }
    - { port: 3306, service: mysql, severity: high }
    - { port: 5432, service: postgres, severity: high }
    - { port: 6379, service: redis, severity: high }
    - { port: 9200, service: elasticsearch, severity: high }
    - { port: 11211, service: memcached, severity: high }
    - { port: 27017, service: mongodb, severity: high }
  liveness_ports: [80, 443]
  concurrency: 4
fix_hints:
  any: 'Restrict the security group/firewall: SSH only from a VPN/office range or replace it with SSM Session Manager; database ports only from the application security group. If this scan ran from an allowlisted network, the port may be correctly restricted elsewhere; re-check from an outside network.'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/Attack_Surface_Analysis_Cheat_Sheet.html
added_by: seed
review: approved
```

- [ ] **Step 6: Run tests and typecheck**

Run: `npx vitest run test/util test/checks && npx tsc -p tsconfig.json`
Expected: all tests PASS (the seed catalog now has 16 instances); `tsc` exits 0.

- [ ] **Step 7: Commit**

```bash
git add src/util/pool.ts src/checks/types/port-exposure.ts src/checks/registry.ts knowledge/checks/ports-exposed.yaml test/util/pool.test.ts test/checks/types/port-exposure.test.ts
git commit -m "feat(checks): add host port exposure check with reachability guard"
```

---

### Task 15: Findings: schema, ids, diff, fix selection, store and `--no-ai` mapping

**Files:**
- Create: `src/findings/schema.ts`, `src/findings/ids.ts`, `src/findings/diff.ts`, `src/findings/fix.ts`, `src/findings/from-results.ts`, `src/findings/store.ts`
- Test: `test/findings/schema.test.ts`, `test/findings/diff.test.ts`, `test/findings/fix.test.ts`, `test/findings/from-results.test.ts`, `test/findings/store.test.ts`

**Interfaces:**
- Consumes: `EVIDENCE_ID_PATTERN` (Task 8); `CheckInstance`, `CheckInstanceSchema` (Task 9); `Stack` (Task 2); `CheckResult`, `FINDING_STATUSES`, `OUTCOMES`, `SEVERITIES`, `FindingStatus` (Task 1); `projectStateDir` (Task 1)
- Produces:
  - `CheckResultSchema`, `FindingSchema`, `type Finding`
  - `ScanDiffSchema`, `type ScanDiff`, `ScanRecordSchema`, `type ScanRecord`
  - `findingId(checkId, target, cve?)`, `resultKey(r)`
  - `diffScans(previous, current: { results; findings }): ScanDiff`
  - `selectFix(instance, stack): { where; how; side_effects }`
  - `resultsToFindings(results, instances: ReadonlyMap<string, CheckInstance>, previous, stack, now): Finding[]`
  - `class FindingsStore`:
    - `constructor(projectDir)`
    - `latest(): Promise<ScanRecord | undefined>`
    - `write(record): Promise<void>`

- [ ] **Step 1: Write the failing tests**

Create a shared fixture builder at the top of each test file as shown.

`test/findings/schema.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { FindingSchema } from '../../src/findings/schema.js';

const base = {
  id: 'hdr-hsts@app',
  check_id: 'hdr-hsts',
  target: 'app',
  severity: 'medium',
  status: 'open',
  title: 'HSTS',
  evidence: ['ev_20261028T100000Z_0a1b2c3d'],
  reasoning: 'missing',
  first_seen: '2026-10-28T10:00:00.000Z',
  last_seen: '2026-10-28T10:00:00.000Z',
  verified_at: '2026-10-28T10:00:00.000Z',
};

describe('FindingSchema', () => {
  it('accepts a finding with evidence and defaults refs/knowledge', () => {
    expect(FindingSchema.parse(base)).toMatchObject({ refs: [], knowledge: [] });
  });
  it('requires at least one evidence id', () => {
    const r = FindingSchema.safeParse({ ...base, evidence: [] });
    expect(r.success).toBe(false);
    expect(JSON.stringify(r.error?.issues)).toContain('at least one evidence id');
  });
  it('rejects anything that is not an evidence id', () => {
    expect(FindingSchema.safeParse({ ...base, evidence: ['trust me'] }).success).toBe(false);
  });
});
```

`test/findings/diff.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { diffScans } from '../../src/findings/diff.js';
import type { Finding, ScanRecord } from '../../src/findings/schema.js';
import type { CheckResult, FindingStatus, Outcome } from '../../src/types.js';

const EV = 'ev_20261028T100000Z_00000000';
const T = '2026-10-28T10:00:00.000Z';
const result = (check_id: string, outcome: Outcome): CheckResult => ({ check_id, target: 'app', title: check_id, outcome, severity: 'low', observed: '', evidence_id: EV });
const finding = (check_id: string, status: FindingStatus): Finding => ({
  id: `${check_id}@app`, check_id, target: 'app', severity: 'low', status, title: check_id, evidence: [EV], reasoning: 'r', refs: [], knowledge: [], first_seen: T, last_seen: T, verified_at: T,
});
const record = (results: CheckResult[], findings: Finding[]): ScanRecord => ({
  schema: 1, scanned_at: T, scan_label: 't', mode: 'no-ai', results, findings, diff: { new: [], fixed: [], regressed: [] },
});

describe('diffScans', () => {
  it('treats everything open as new on the first scan', () => {
    expect(diffScans(undefined, { results: [result('a', 'fail')], findings: [finding('a', 'open')] })).toEqual({ new: ['a@app'], fixed: [], regressed: [] });
  });
  it('reports fixed, regressed and unchanged correctly', () => {
    const previous = record(
      [result('a', 'fail'), result('b', 'pass'), result('c', 'fail')],
      [finding('a', 'open'), finding('c', 'open')],
    );
    const current = {
      results: [result('a', 'pass'), result('b', 'fail'), result('c', 'fail')],
      findings: [finding('a', 'fixed'), finding('b', 'open'), finding('c', 'open')],
    };
    expect(diffScans(previous, current)).toEqual({ new: [], fixed: ['a@app'], regressed: ['b@app'] });
  });
});
```

`test/findings/fix.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { CheckInstanceSchema } from '../../src/checks/catalog.js';
import { selectFix } from '../../src/findings/fix.js';

const instance = CheckInstanceSchema.parse({
  id: 'hdr-hsts',
  type: 'http_header',
  title: 'HSTS',
  severity: 'medium',
  applies_to: ['web'],
  fix_hints: { nginx: 'add_header ...', express: 'helmet.hsts()', any: 'general advice' },
  side_effects: ['header-budget-proxy-buffer'],
  source_url: 'https://example.com/guide',
  review: 'approved',
});

describe('selectFix', () => {
  it('keeps hints matching the stack plus "any"', () => {
    expect(selectFix(instance, { proxy: 'nginx', frontend: 'angular' })).toEqual({
      where: 'nginx, any',
      how: '[nginx] add_header ...\n[any] general advice',
      side_effects: ['header-budget-proxy-buffer'],
    });
  });
  it('falls back to every hint when the stack is unknown', () => {
    expect(selectFix({ ...instance, fix_hints: { nginx: 'n', express: 'e' } }, {}).where).toBe('nginx, express');
  });
});
```

`test/findings/from-results.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { CheckInstanceSchema, type CheckInstance } from '../../src/checks/catalog.js';
import { resultsToFindings } from '../../src/findings/from-results.js';
import type { ScanRecord } from '../../src/findings/schema.js';
import type { CheckResult, Outcome, Severity } from '../../src/types.js';

const EV = 'ev_20261028T100000Z_00000000';
const NOW = new Date('2026-10-28T11:00:00.000Z');
const inst = CheckInstanceSchema.parse({
  id: 'hdr-hsts', type: 'http_header', title: 'HSTS', severity: 'medium', applies_to: ['web'],
  fix_hints: { nginx: 'add_header ...' }, source_url: 'https://example.com/guide', review: 'approved',
});
const INSTANCES = new Map<string, CheckInstance>([[inst.id, inst]]);
const result = (outcome: Outcome, severity: Severity = 'medium'): CheckResult => ({
  check_id: 'hdr-hsts', target: 'app', title: 'HSTS', outcome, severity, observed: 'seen', evidence_id: EV,
});

describe('resultsToFindings', () => {
  it('maps fail to open with fix, refs and knowledge', () => {
    const [f] = resultsToFindings([result('fail')], INSTANCES, undefined, { proxy: 'nginx' }, NOW);
    expect(f).toMatchObject({
      id: 'hdr-hsts@app', status: 'open', severity: 'medium', evidence: [EV], refs: ['https://example.com/guide'], knowledge: ['hdr-hsts'],
      first_seen: NOW.toISOString(), fix: { where: 'nginx' },
    });
    expect(f?.reasoning).toContain('No AI triage');
    expect(f?.severity_reason).toBeUndefined();
  });

  it('records why severity differs from the instance default', () => {
    const [f] = resultsToFindings([result('fail', 'high')], INSTANCES, undefined, {}, NOW);
    expect(f?.severity_reason).toContain('default medium');
  });

  it('maps unverifiable and error to unverifiable without a fix', () => {
    const findings = resultsToFindings([result('unverifiable'), { ...result('error'), target: 'api' }], INSTANCES, undefined, {}, NOW);
    expect(findings.map((f) => [f.id, f.status, f.fix])).toEqual([
      ['hdr-hsts@app', 'unverifiable', undefined],
      ['hdr-hsts@api', 'unverifiable', undefined],
    ]);
  });

  it('drops passes unless the previous scan had the finding open, then marks it fixed and keeps first_seen', () => {
    expect(resultsToFindings([result('pass')], INSTANCES, undefined, {}, NOW)).toEqual([]);
    const previous = {
      schema: 1, scanned_at: '2026-10-27T10:00:00.000Z', scan_label: 't', mode: 'no-ai', results: [],
      findings: resultsToFindings([result('fail')], INSTANCES, undefined, {}, new Date('2026-10-27T10:00:00.000Z')),
      diff: { new: [], fixed: [], regressed: [] },
    } satisfies ScanRecord;
    const [f] = resultsToFindings([result('pass')], INSTANCES, previous, {}, NOW);
    expect(f).toMatchObject({ status: 'fixed', first_seen: '2026-10-27T10:00:00.000Z', last_seen: NOW.toISOString() });
  });
});
```

`test/findings/store.test.ts`:
```ts
import { readdirSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import type { ScanRecord } from '../../src/findings/schema.js';
import { FindingsStore } from '../../src/findings/store.js';
import { tempDir } from '../helpers/tmp.js';

const record = (scanned_at: string): ScanRecord => ({
  schema: 1, scanned_at, scan_label: 'office', mode: 'no-ai', results: [], findings: [], diff: { new: [], fixed: [], regressed: [] },
});

describe('FindingsStore', () => {
  it('returns undefined before the first scan', async () => {
    expect(await new FindingsStore(await tempDir()).latest()).toBeUndefined();
  });
  it('writes latest.json and one history file per scan', async () => {
    const dir = await tempDir();
    const store = new FindingsStore(dir);
    await store.write(record('2026-10-28T10:00:00.000Z'));
    await store.write(record('2026-10-28T10:05:00.000Z'));
    expect((await store.latest())?.scanned_at).toBe('2026-10-28T10:05:00.000Z');
    expect(readdirSync(path.join(dir, '.secagent', 'findings', 'history')).sort()).toEqual([
      '20261028T100000.000Z.json',
      '20261028T100500.000Z.json',
    ]);
  });
  it('refuses to write an invalid record', async () => {
    const bad = { ...record('2026-10-28T10:00:00.000Z'), scan_label: 42 } as unknown as ScanRecord;
    await expect(new FindingsStore(await tempDir()).write(bad)).rejects.toThrow();
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/findings`
Expected: FAIL, because the modules can't be resolved.

- [ ] **Step 3: Implement the findings modules**

`src/findings/schema.ts`:
```ts
import { z } from 'zod';
import { EVIDENCE_ID_PATTERN } from '../evidence/store.js';
import { FINDING_STATUSES, OUTCOMES, SEVERITIES } from '../types.js';

export const CheckResultSchema = z.object({
  check_id: z.string().min(1),
  target: z.string().min(1),
  title: z.string().min(1),
  outcome: z.enum(OUTCOMES),
  severity: z.enum(SEVERITIES),
  observed: z.string(),
  evidence_id: z.string().regex(EVIDENCE_ID_PATTERN),
  details: z.record(z.string(), z.unknown()).optional(),
});

export const FindingSchema = z.object({
  id: z.string().min(1),
  check_id: z.string().min(1),
  target: z.string().min(1),
  severity: z.enum(SEVERITIES),
  severity_reason: z.string().optional(),
  status: z.enum(FINDING_STATUSES),
  title: z.string().min(1),
  evidence: z
    .array(z.string().regex(EVIDENCE_ID_PATTERN, 'not an evidence id'))
    .min(1, 'a finding must cite at least one evidence id'),
  reasoning: z.string().min(1),
  fix: z.object({ where: z.string(), how: z.string(), side_effects: z.array(z.string()).default([]) }).optional(),
  refs: z.array(z.url()).default([]),
  knowledge: z.array(z.string()).default([]),
  first_seen: z.iso.datetime(),
  last_seen: z.iso.datetime(),
  verified_at: z.iso.datetime(),
});
export type Finding = z.infer<typeof FindingSchema>;

export const ScanDiffSchema = z.object({
  new: z.array(z.string()),
  fixed: z.array(z.string()),
  regressed: z.array(z.string()),
});
export type ScanDiff = z.infer<typeof ScanDiffSchema>;

export const ScanRecordSchema = z.object({
  schema: z.literal(1),
  scanned_at: z.iso.datetime(),
  scan_label: z.string(),
  mode: z.enum(['no-ai', 'agent']),
  results: z.array(CheckResultSchema),
  findings: z.array(FindingSchema),
  diff: ScanDiffSchema,
});
export type ScanRecord = z.infer<typeof ScanRecordSchema>;
```

`src/findings/ids.ts`:
```ts
/** Stable across scans so diffs can match findings: "<check>@<target>" or "<check>:<CVE>@<host>". */
export function findingId(checkId: string, target: string, cve?: string): string {
  return cve ? `${checkId}:${cve}@${target}` : `${checkId}@${target}`;
}

export function resultKey(r: { check_id: string; target: string }): string {
  return findingId(r.check_id, r.target);
}
```

`src/findings/diff.ts`:
```ts
import type { CheckResult } from '../types.js';
import { resultKey } from './ids.js';
import type { Finding, ScanDiff, ScanRecord } from './schema.js';

/**
 * new: open now, and neither open nor passing in the previous scan.
 * regressed: open now, passing in the previous scan.
 * fixed: open in the previous scan, passing now.
 */
export function diffScans(
  previous: ScanRecord | undefined,
  current: { results: readonly CheckResult[]; findings: readonly Finding[] },
): ScanDiff {
  const prevOpen = new Set((previous?.findings ?? []).filter((f) => f.status === 'open').map((f) => f.id));
  const prevPass = new Set((previous?.results ?? []).filter((r) => r.outcome === 'pass').map(resultKey));
  const curOpen = current.findings.filter((f) => f.status === 'open').map((f) => f.id);
  const curPass = new Set(current.results.filter((r) => r.outcome === 'pass').map(resultKey));
  return {
    new: curOpen.filter((id) => !prevOpen.has(id) && !prevPass.has(id)),
    fixed: [...prevOpen].filter((id) => curPass.has(id)),
    regressed: curOpen.filter((id) => prevPass.has(id)),
  };
}
```

`src/findings/fix.ts`:
```ts
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
```

`src/findings/from-results.ts`:
```ts
import type { CheckInstance } from '../checks/catalog.js';
import type { Stack } from '../project/schema.js';
import type { CheckResult, FindingStatus } from '../types.js';
import { selectFix } from './fix.js';
import { resultKey } from './ids.js';
import type { Finding, ScanRecord } from './schema.js';

/** Deterministic (--no-ai) mapping: fail → open, unverifiable/error → unverifiable, previously open now passing → fixed. */
export function resultsToFindings(
  results: readonly CheckResult[],
  instances: ReadonlyMap<string, CheckInstance>,
  previous: ScanRecord | undefined,
  stack: Stack,
  now: Date,
): Finding[] {
  const previousById = new Map((previous?.findings ?? []).map((f) => [f.id, f] as const));
  const iso = now.toISOString();
  const findings: Finding[] = [];

  for (const r of results) {
    const id = resultKey(r);
    const prev = previousById.get(id);
    const status: FindingStatus | undefined =
      r.outcome === 'fail'
        ? 'open'
        : r.outcome === 'unverifiable' || r.outcome === 'error'
          ? 'unverifiable'
          : prev?.status === 'open'
            ? 'fixed'
            : undefined;
    if (status === undefined) continue;

    const inst = instances.get(r.check_id);
    findings.push({
      id,
      check_id: r.check_id,
      target: r.target,
      severity: r.severity,
      ...(inst && r.severity !== inst.severity
        ? { severity_reason: `Set by the ${inst.type} check from what it observed (default ${inst.severity}).` }
        : {}),
      status,
      title: r.title,
      evidence: [r.evidence_id],
      reasoning: `No AI triage (--no-ai). Check outcome: ${r.outcome}. Observed: ${r.observed}`,
      ...(inst && status === 'open' ? { fix: selectFix(inst, stack) } : {}),
      refs: inst ? [inst.source_url] : [],
      knowledge: inst ? [inst.id] : [],
      first_seen: prev?.first_seen ?? iso,
      last_seen: iso,
      verified_at: iso,
    });
  }
  return findings;
}
```

`src/findings/store.ts`:
```ts
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { projectStateDir } from '../paths.js';
import { ScanRecordSchema, type ScanRecord } from './schema.js';

export class FindingsStore {
  readonly dir: string;

  constructor(projectDir: string) {
    this.dir = path.join(projectStateDir(projectDir), 'findings');
  }

  async latest(): Promise<ScanRecord | undefined> {
    let text: string;
    try {
      text = await readFile(path.join(this.dir, 'latest.json'), 'utf8');
    } catch (e) {
      if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
      throw e;
    }
    return ScanRecordSchema.parse(JSON.parse(text));
  }

  async write(record: ScanRecord): Promise<void> {
    const valid = ScanRecordSchema.parse(record);
    const json = `${JSON.stringify(valid, null, 2)}\n`;
    await mkdir(path.join(this.dir, 'history'), { recursive: true });
    await writeFile(path.join(this.dir, 'history', `${valid.scanned_at.replace(/[-:]/g, '')}.json`), json, 'utf8');
    await writeFile(path.join(this.dir, 'latest.json'), json, 'utf8');
  }
}
```

- [ ] **Step 4: Run tests and typecheck**

Run: `npx vitest run test/findings && npx tsc -p tsconfig.json`
Expected: all tests PASS (3 schema, 2 diff, 2 fix, 4 from-results, 3 store); `tsc` exits 0.

- [ ] **Step 5: Commit**

```bash
git add src/findings test/findings
git commit -m "feat(findings): add finding schema, scan diff, fix selection and store"
```

---

### Task 16: `scanNoAi` and the CLI

**Files:**
- Create: `src/scan/no-ai.ts`, `src/cli.ts`
- Test: `test/scan/no-ai.test.ts`, `test/cli.test.ts`, `test/checks/registry.test.ts`

**Interfaces:**
- Consumes:
  - `loadProject`, `ProjectConfigError` (Task 2); `initProject` (Task 4); `Scope` (Task 5)
  - `ScopedNet`, `NetClient`, `EvidenceStore`, `CheckContext` (Task 8)
  - `loadCheckInstances`, `CatalogError`, `runChecks`, `AnyCheckType` (Task 9); `CHECK_TYPES` (Tasks 10–14)
  - `FindingsStore`, `resultsToFindings`, `diffScans`, `resultKey`, `ScanRecord` (Task 15)
  - `GLOBAL_CHECKS_DIR` (Task 1); `SEVERITY_RANK` (Task 1)
- Produces:
  - `interface ScanDeps { net?: NetClient; now?: () => Date; checksDir?: string; types?: ReadonlyMap<string, AnyCheckType> }`
  - `scanNoAi(projectDir, deps?): Promise<ScanRecord>`
  - CLI exports:
    - `main(argv): Promise<number>`, `class UsageError`
    - `parseTargetSpec(spec)`, `parseHostSpec(spec)`
    - `formatScan(record): string[]`

- [ ] **Step 1: Write the failing tests**

`test/checks/registry.test.ts`:
```ts
import { describe, expect, it } from 'vitest';
import { CHECK_TYPES } from '../../src/checks/registry.js';

describe('CHECK_TYPES', () => {
  it('registers all seven external check types', () => {
    expect([...CHECK_TYPES.keys()].sort()).toEqual([
      'exposed_path',
      'header_budget',
      'http_cookie',
      'http_header',
      'http_redirect',
      'port_exposure',
      'tls',
    ]);
  });
});
```

`test/scan/no-ai.test.ts`:
```ts
import { existsSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { loadCheckInstances } from '../../src/checks/catalog.js';
import { CHECK_TYPES } from '../../src/checks/registry.js';
import { NetError } from '../../src/net/errors.js';
import type { NetClient } from '../../src/net/scoped.js';
import { GLOBAL_CHECKS_DIR } from '../../src/paths.js';
import { initProject } from '../../src/project/init.js';
import { scanNoAi } from '../../src/scan/no-ai.js';
import { FIXED_NOW, fakeObs } from '../helpers/ctx.js';
import { startHttps, type Running } from '../helpers/servers.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

const HSTS_CHECK = `id: hdr-hsts
type: http_header
title: HSTS enabled
severity: medium
applies_to: [web]
params:
  header: strict-transport-security
  must_exist: true
  min_max_age: 15552000
fix_hints:
  nginx: 'add_header Strict-Transport-Security "max-age=31536000" always;'
source_url: https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html
review: approved
`;

const running: Running[] = [];
afterEach(async () => {
  await Promise.all(running.splice(0).map((s) => s.close()));
});

describe('scanNoAi', () => {
  it('opens a finding with evidence, then marks it fixed when the header appears', async () => {
    let sendHsts = false;
    const s = await startHttps((_req, res) => {
      if (sendHsts) res.setHeader('strict-transport-security', 'max-age=31536000');
      res.end('ok');
    });
    running.push(s);
    const dir = await tempDir();
    const checksDir = await tempDir();
    await writeFiles(checksDir, { 'hdr-hsts.yaml': HSTS_CHECK });
    await writeFiles(dir, { 'nginx.conf': '' });
    await initProject(dir, { scanLabel: 'test-net', targets: [{ id: 'app', url: s.url, type: 'web', env: 'test' }] });

    const first = await scanNoAi(dir, { checksDir, now: () => new Date('2026-10-28T10:00:00.000Z') });
    expect(first.findings).toHaveLength(1);
    const finding = first.findings[0];
    expect(finding).toMatchObject({ id: 'hdr-hsts@app', status: 'open', severity: 'medium' });
    expect(finding?.fix?.how).toContain('[nginx]');
    expect(existsSync(path.join(dir, '.secagent', 'evidence', `${finding?.evidence[0]}.json`))).toBe(true);
    expect(first.diff.new).toEqual(['hdr-hsts@app']);

    sendHsts = true;
    const second = await scanNoAi(dir, { checksDir, now: () => new Date('2026-10-28T10:05:00.000Z') });
    expect(second.diff.fixed).toEqual(['hdr-hsts@app']);
    expect(second.findings[0]).toMatchObject({ status: 'fixed', first_seen: '2026-10-28T10:00:00.000Z' });
    expect(existsSync(path.join(dir, '.secagent', 'findings', 'latest.json'))).toBe(true);
  });

  it('runs every applicable seed check without errors (fake network)', async () => {
    const dir = await tempDir();
    await initProject(dir, {
      targets: [{ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' }],
      hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }],
    });
    const net: NetClient = {
      http: async (url) => fakeObs({ url, bodySnippet: '<html></html>' }),
      tls: async () => {
        throw new NetError('ECONNREFUSED', 'refused');
      },
      tcp: async () => 'closed',
    };
    const record = await scanNoAi(dir, { net, now: () => FIXED_NOW });
    const instances = await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES);
    const expected = instances.filter((i) => i.applies_to.includes('web')).length + instances.filter((i) => i.applies_to.includes('host')).length;
    expect(record.results).toHaveLength(expected);
    expect(record.results.filter((r) => r.outcome === 'error')).toEqual([]);
  });
});
```

`test/cli.test.ts`:
```ts
import { afterEach, describe, expect, it, vi } from 'vitest';
import { formatScan, main, parseHostSpec, parseTargetSpec, UsageError } from '../src/cli.js';
import { loadProject } from '../src/project/schema.js';
import { tempDir } from './helpers/tmp.js';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('spec parsers', () => {
  it('parses target and host specs', () => {
    expect(parseTargetSpec('app=https://app.example.com,web,prod')).toEqual({ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' });
    expect(parseHostSpec('web-1=203.0.113.10,prod')).toEqual({ name: 'web-1', address: '203.0.113.10', env: 'prod' });
  });
  it('rejects malformed specs with a usage error', () => {
    expect(() => parseTargetSpec('app=ftp://x,web,prod')).toThrow(UsageError);
    expect(() => parseHostSpec('web-1')).toThrow(UsageError);
  });
});

describe('main', () => {
  it('init writes targets and hosts from flags', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = await tempDir();
    const code = await main(['init', '--dir', dir, '--scan-label', 'office', '--target', 'app=https://app.example.com,web,prod', '--host', 'web-1=203.0.113.10,prod']);
    expect(code).toBe(0);
    const p = await loadProject(dir);
    expect(p.network.scan_label).toBe('office');
    expect(p.targets[0]).toMatchObject({ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' });
    expect(p.hosts[0]).toMatchObject({ name: 'web-1', address: '203.0.113.10', env: 'prod' });
  });

  it('scan without --no-ai explains how to run it', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['scan', '--dir', await tempDir()])).toBe(1);
    expect(error).toHaveBeenCalledWith(expect.stringContaining('secagent scan --no-ai'));
  });

  it('scan --no-ai before init points at init', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['scan', '--no-ai', '--dir', await tempDir()])).toBe(1);
    expect(error).toHaveBeenCalledWith(expect.stringContaining('secagent init'));
  });

  it('rejects unknown commands and unknown flags', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['nope'])).toBe(1);
    expect(await main(['init', '--bogus'])).toBe(1);
  });

  it('prints usage with no command', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    expect(await main([])).toBe(0);
    expect(log).toHaveBeenCalledWith(expect.stringContaining('secagent <command>'));
  });
});

describe('formatScan', () => {
  it('lists findings most severe first with the observed text', () => {
    const EV = 'ev_20261028T100000Z_00000000';
    const T = '2026-10-28T10:00:00.000Z';
    const lines = formatScan({
      schema: 1, scanned_at: T, scan_label: 'office', mode: 'no-ai',
      results: [
        { check_id: 'a', target: 'app', title: 'a', outcome: 'fail', severity: 'low', observed: 'low thing', evidence_id: EV },
        { check_id: 'b', target: 'app', title: 'b', outcome: 'fail', severity: 'high', observed: 'big thing', evidence_id: EV },
      ],
      findings: (['a', 'b'] as const).map((c) => ({
        id: `${c}@app`, check_id: c, target: 'app', severity: c === 'a' ? ('low' as const) : ('high' as const), status: 'open' as const,
        title: c, evidence: [EV], reasoning: 'r', refs: [], knowledge: [], first_seen: T, last_seen: T, verified_at: T,
      })),
      diff: { new: ['a@app', 'b@app'], fixed: [], regressed: [] },
    });
    expect(lines[1]).toContain('open 2');
    expect(lines[2]).toContain('HIGH');
    expect(lines[2]).toContain('big thing');
    expect(lines[3]).toContain('LOW');
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/checks/registry.test.ts test/scan/no-ai.test.ts test/cli.test.ts`
Expected: `registry.test.ts` PASSES (all seven types are registered by now). The other two FAIL, because `../../src/scan/no-ai.js` and `../src/cli.js` can't be resolved.

- [ ] **Step 3: Implement `src/scan/no-ai.ts`**

```ts
import { loadCheckInstances } from '../checks/catalog.js';
import type { AnyCheckType } from '../checks/check-type.js';
import type { CheckContext } from '../checks/context.js';
import { CHECK_TYPES } from '../checks/registry.js';
import { runChecks } from '../checks/runner.js';
import { EvidenceStore } from '../evidence/store.js';
import { diffScans } from '../findings/diff.js';
import { resultsToFindings } from '../findings/from-results.js';
import type { ScanRecord } from '../findings/schema.js';
import { FindingsStore } from '../findings/store.js';
import { ScopedNet, type NetClient } from '../net/scoped.js';
import { GLOBAL_CHECKS_DIR } from '../paths.js';
import { loadProject } from '../project/schema.js';
import { Scope } from '../project/scope.js';
import type { CheckResult } from '../types.js';

export interface ScanDeps {
  /** Defaults to a ScopedNet over project.yaml; tests may inject a fake. */
  net?: NetClient;
  now?: () => Date;
  checksDir?: string;
  types?: ReadonlyMap<string, AnyCheckType>;
}

/** Runs every applicable check on every listed target and host, with no AI involvement. */
export async function scanNoAi(projectDir: string, deps: ScanDeps = {}): Promise<ScanRecord> {
  const project = await loadProject(projectDir);
  const now = deps.now ?? (() => new Date());
  const types = deps.types ?? CHECK_TYPES;
  const instances = await loadCheckInstances(deps.checksDir ?? GLOBAL_CHECKS_DIR, types);
  const ctx: CheckContext = {
    project,
    net: deps.net ?? new ScopedNet(new Scope(project), project.network.ip_family),
    evidence: new EvidenceStore(projectDir, project.network.scan_label, now),
    now,
    memo: new Map(),
  };

  const results: CheckResult[] = [];
  for (const target of project.targets) results.push(...(await runChecks(ctx, { kind: 'target', target }, instances, types)));
  for (const host of project.hosts) results.push(...(await runChecks(ctx, { kind: 'host', host }, instances, types)));

  const store = new FindingsStore(projectDir);
  const previous = await store.latest();
  const scannedAt = now();
  const findings = resultsToFindings(results, new Map(instances.map((i) => [i.id, i])), previous, project.stack, scannedAt);
  const record: ScanRecord = {
    schema: 1,
    scanned_at: scannedAt.toISOString(),
    scan_label: project.network.scan_label,
    mode: 'no-ai',
    results,
    findings,
    diff: diffScans(previous, { results, findings }),
  };
  await store.write(record);
  return record;
}
```

- [ ] **Step 4: Implement `src/cli.ts`**

```ts
#!/usr/bin/env node
import { realpathSync } from 'node:fs';
import path from 'node:path';
import { pathToFileURL } from 'node:url';
import { parseArgs } from 'node:util';
import { CatalogError } from './checks/catalog.js';
import { resultKey } from './findings/ids.js';
import type { ScanRecord } from './findings/schema.js';
import { initProject } from './project/init.js';
import { ProjectConfigError } from './project/schema.js';
import { scanNoAi } from './scan/no-ai.js';
import { SEVERITY_RANK } from './types.js';

export class UsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'UsageError';
  }
}

const USAGE = `secagent <command> [options]

Commands:
  init    Create .secagent/ in a project, detect its stack, write project.yaml
            --dir <path>           project directory (default: .)
            --name <name>          project name (default: directory name)
            --scan-label <label>   name of the network you scan from, e.g. office
            --target <spec>        id=https://host,web|api,env   (repeatable)
            --host <spec>          name=address,env              (repeatable)
  scan    Run every check against the targets and hosts in project.yaml
            --dir <path>
            --no-ai                deterministic checks only, no AI triage
`;

export function parseTargetSpec(spec: string): { id: string; url: string; type: 'web' | 'api'; env: string } {
  const match = /^([a-z0-9][a-z0-9-]*)=(https?:\/\/[^,]+),(web|api),([^,]+)$/.exec(spec);
  if (!match) throw new UsageError(`--target must look like id=https://host,web|api,env (got "${spec}")`);
  const [, id = '', url = '', type = 'web', env = ''] = match;
  return { id, url, type: type as 'web' | 'api', env };
}

export function parseHostSpec(spec: string): { name: string; address: string; env: string } {
  const match = /^([a-z0-9][a-z0-9-]*)=([^,]+),([^,]+)$/.exec(spec);
  if (!match) throw new UsageError(`--host must look like name=address,env (got "${spec}")`);
  const [, name = '', address = '', env = ''] = match;
  return { name, address, env };
}

export function formatScan(record: ScanRecord): string[] {
  const counts = new Map<string, number>();
  for (const f of record.findings) counts.set(f.status, (counts.get(f.status) ?? 0) + 1);
  const observed = new Map(record.results.map((r) => [resultKey(r), r.observed] as const));
  const lines = [
    `Scan ${record.scanned_at} from network "${record.scan_label}": ${record.results.length} check results, ${record.findings.length} findings`,
    `  ${[...counts].map(([status, n]) => `${status} ${n}`).join(' · ') || 'nothing to report'}`,
  ];
  const sorted = [...record.findings].sort(
    (a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id),
  );
  for (const f of sorted) {
    lines.push(`  ${f.severity.toUpperCase().padEnd(8)} ${f.status.padEnd(12)} ${f.id}  ${observed.get(f.id) ?? ''}`);
  }
  lines.push(`Diff vs previous scan: new ${record.diff.new.length}, fixed ${record.diff.fixed.length}, regressed ${record.diff.regressed.length}`);
  lines.push('Details: .secagent/findings/latest.json · evidence: .secagent/evidence/');
  return lines;
}

async function runInit(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: {
      dir: { type: 'string', default: '.' },
      name: { type: 'string' },
      'scan-label': { type: 'string' },
      target: { type: 'string', multiple: true },
      host: { type: 'string', multiple: true },
    },
  });
  const targets = (values.target ?? []).map(parseTargetSpec);
  const hosts = (values.host ?? []).map(parseHostSpec);
  const result = await initProject(path.resolve(values.dir), { name: values.name, scanLabel: values['scan-label'], targets, hosts });

  console.log(result.created ? `Created ${result.stateDir}` : `Updated ${result.stateDir}`);
  if (!result.created && (targets.length > 0 || hosts.length > 0)) {
    console.log('project.yaml already existed: --target/--host were ignored. Edit .secagent/project.yaml to change them.');
  }
  console.log(`Detected stack: ${JSON.stringify(result.config.stack)}`);
  for (const marker of result.detection.markers) console.log(`  ${marker}`);
  if (result.config.targets.length === 0 && result.config.hosts.length === 0) {
    console.log('No targets or hosts yet. Add them to .secagent/project.yaml before scanning.');
  }
  return 0;
}

async function runScan(args: string[]): Promise<number> {
  const { values } = parseArgs({
    args,
    strict: true,
    options: { dir: { type: 'string', default: '.' }, 'no-ai': { type: 'boolean', default: false } },
  });
  if (!values['no-ai']) {
    throw new UsageError(
      'AI-triaged scans run inside your AI client through the secagent MCP server. For a deterministic scan without AI, run: secagent scan --no-ai',
    );
  }
  const record = await scanNoAi(path.resolve(values.dir));
  for (const line of formatScan(record)) console.log(line);
  return 0;
}

export async function main(argv: readonly string[]): Promise<number> {
  const [command, ...rest] = argv;
  try {
    switch (command) {
      case 'init':
        return await runInit(rest);
      case 'scan':
        return await runScan(rest);
      case undefined:
      case 'help':
      case '--help':
      case '-h':
        console.log(USAGE);
        return 0;
      default:
        console.error(`Unknown command "${command}".\n\n${USAGE}`);
        return 1;
    }
  } catch (e) {
    if (e instanceof UsageError || e instanceof ProjectConfigError || e instanceof CatalogError) {
      console.error(e.message);
      return 1;
    }
    if (e instanceof TypeError && String((e as NodeJS.ErrnoException).code ?? '').startsWith('ERR_PARSE_ARGS')) {
      console.error(`${e.message}\n\n${USAGE}`);
      return 1;
    }
    throw e;
  }
}

const invokedPath = process.argv[1];
if (invokedPath && import.meta.url === pathToFileURL(realpathSync(invokedPath)).href) {
  main(process.argv.slice(2)).then(
    (code) => {
      process.exitCode = code;
    },
    (e: unknown) => {
      console.error(e);
      process.exitCode = 2;
    },
  );
}
```

- [ ] **Step 5: Run the full suite, typecheck and build**

Run: `npx vitest run && npx tsc -p tsconfig.json && npm run build`
Expected:
- every test PASSES (the lab e2e file doesn't exist yet);
- `tsc` exits 0;
- `dist/cli.js` exists and starts with `#!/usr/bin/env node`.

- [ ] **Step 6: Smoke-test the CLI by hand**

Run:
```bash
D=$(mktemp -d) && npm run --silent dev -- init --dir "$D" --scan-label local --target example=https://example.com,web,demo && cat "$D/.secagent/project.yaml" && npm run --silent dev -- scan --dir "$D"; echo "exit=$?"
```
Expected:
- `Created …/.secagent`, then the YAML listing target `example`;
- the scan prints the `--no-ai` hint and `exit=1`.

Don't run a real scan against example.com; real scans are exercised in Task 17's lab.

- [ ] **Step 7: Commit**

```bash
git add src/scan/no-ai.ts src/cli.ts test/scan/no-ai.test.ts test/cli.test.ts test/checks/registry.test.ts
git commit -m "feat(cli): add init and scan --no-ai commands"
```

---

### Task 17: Docker lab and end-to-end verification

**Files:**
- Create:
  - `lab/README.md`, `lab/docker-compose.yml`, `lab/gen-certs.sh`
  - `lab/bad-site/default.conf`, `lab/bad-site/html/index.html`, `lab/bad-site/html/app.js`, `lab/bad-site/html/app.js.map`, `lab/bad-site/html/.env`, `lab/bad-site/html/git-config.txt`
  - `lab/good-site/default.conf`, `lab/good-site/html/index.html`, `lab/good-site/html/app.js`
  - `lab/project/.secagent/…` (generated by `secagent init`)
- Test: `test/lab.e2e.test.ts`

**Interfaces:**
- Consumes: CLI `init` (Task 16); `scanNoAi` (Task 16); `tempDir` (Task 2)
- Produces: a reproducible bad/good target pair at `172.31.250.10` / `172.31.250.11`, and an opt-in e2e test (`SECAGENT_LAB=1`)

During planning, `nginx:1.30.6` (OpenSSL 3.5.7, no system `MinProtocol`) was confirmed to accept TLS 1.0/1.1 and non-AEAD TLS 1.2 with the bad-site TLS settings below. The lab needs Linux, because the host routes to Docker bridge IPs; Docker Desktop on macOS doesn't.

- [ ] **Step 1: Write the lab files**

`lab/docker-compose.yml`:
```yaml
name: secagent-lab
services:
  bad-site:
    image: nginx:1.30.6
    volumes:
      - ./bad-site/default.conf:/etc/nginx/conf.d/default.conf:ro
      - ./bad-site/html:/usr/share/nginx/html:ro
      - ./certs/bad:/etc/nginx/certs:ro
    networks:
      lab:
        ipv4_address: 172.31.250.10
  good-site:
    image: nginx:1.30.6
    volumes:
      - ./good-site/default.conf:/etc/nginx/conf.d/default.conf:ro
      - ./good-site/html:/usr/share/nginx/html:ro
      - ./certs/good:/etc/nginx/certs:ro
    networks:
      lab:
        ipv4_address: 172.31.250.11
networks:
  lab:
    ipam:
      config:
        - subnet: 172.31.250.0/24
```

`lab/gen-certs.sh`:
```sh
#!/bin/sh
# Self-signed certificates for the lab sites (SAN = the site's IP). Output is gitignored.
set -eu
cd "$(dirname "$0")"
for site in bad:172.31.250.10 good:172.31.250.11; do
  name=${site%%:*}
  ip=${site#*:}
  mkdir -p "certs/$name"
  openssl req -x509 -newkey rsa:2048 -nodes -days 825 -subj "/CN=$ip" \
    -addext "subjectAltName=IP:$ip" \
    -keyout "certs/$name/key.pem" -out "certs/$name/cert.pem" 2>/dev/null
  chmod 644 "certs/$name/key.pem" "certs/$name/cert.pem"
done
echo "certificates written to lab/certs/"
```

`lab/bad-site/default.conf`:
```nginx
# Deliberately insecure. Lab use only.
server {
    listen 80;
    server_tokens on;
    root /usr/share/nginx/html;
    location / { try_files $uri $uri/ /index.html; }
}

server {
    listen 443 ssl;
    server_tokens on;
    ssl_certificate     /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;
    ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;
    ssl_ciphers 'DEFAULT:@SECLEVEL=0';
    root /usr/share/nginx/html;
    add_header X-Powered-By "Express" always;
    add_header Set-Cookie "session=lab-not-a-secret; Path=/" always;
    location = /.git/config { alias /usr/share/nginx/html/git-config.txt; default_type text/plain; }
    location / { try_files $uri $uri/ /index.html; }
}

# Stands in for an exposed database port.
server {
    listen 6379;
    return 200 "not really redis\n";
}
```

`lab/bad-site/html/index.html`:
```html
<!doctype html>
<html><head><title>secagent lab: bad site</title></head>
<body><h1>bad site</h1><script src="/app.js"></script></body></html>
```

`lab/bad-site/html/app.js`:
```js
console.log('secagent lab');
```

`lab/bad-site/html/app.js.map`:
```json
{"version":3,"sources":["app.ts"],"names":[],"mappings":"AAAA"}
```

`lab/bad-site/html/.env`:
```
DB_PASSWORD=lab-not-a-secret
```

`lab/bad-site/html/git-config.txt`:
```
[core]
	repositoryformatversion = 0
```

`lab/good-site/default.conf`:
```nginx
server {
    listen 80;
    server_tokens off;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl;
    server_tokens off;
    ssl_certificate     /etc/nginx/certs/cert.pem;
    ssl_certificate_key /etc/nginx/certs/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_ciphers off;
    root /usr/share/nginx/html;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;
    add_header Set-Cookie "session=lab-not-a-secret; Path=/; Secure; HttpOnly; SameSite=Lax" always;
    # SPA fallback on purpose: /.env and /app.js.map return index.html with 200, which must NOT count as exposed.
    location / { try_files $uri $uri/ /index.html; }
}
```

`lab/good-site/html/index.html`:
```html
<!doctype html>
<html><head><title>secagent lab: good site</title></head>
<body><h1>good site</h1><script src="/app.js"></script></body></html>
```

`lab/good-site/html/app.js`:
```js
console.log('secagent lab');
```

`lab/README.md`:
````markdown
# secagent lab

Two nginx sites on a Docker bridge network (Linux hosts only: the host must route to 172.31.250.0/24):

| Site | Address | Configuration |
|---|---|---|
| bad-site | 172.31.250.10 | Plain HTTP served, no security headers, `server_tokens on`, `X-Powered-By`, insecure cookie, TLS 1.0/1.1 and CBC ciphers, `/.env`, `/.git/config` and a source map exposed, port 6379 open |
| good-site | 172.31.250.11 | Hardened, with an SPA fallback |

Both use self-signed certificates, so `tls-cert-valid` fails on both. That is expected.

```bash
sh lab/gen-certs.sh
docker compose -f lab/docker-compose.yml up -d
npm run dev -- scan --no-ai --dir lab/project
SECAGENT_LAB=1 npx vitest run test/lab.e2e.test.ts
docker compose -f lab/docker-compose.yml down
```

Expected outcomes:

| Check | bad-site | good-site |
|---|---|---|
| http-redirect-https | fail | pass |
| hdr-hsts, hdr-csp, hdr-frame-options, hdr-content-type-options, hdr-referrer-policy, hdr-permissions-policy | fail | pass |
| hdr-x-powered-by, hdr-server-version | fail | pass |
| cookie-flags | fail | pass |
| header-budget | pass | pass |
| exposed-paths | fail (critical: .env, .git/config, app.js.map) | pass |
| tls-no-legacy, tls-modern | fail | pass |
| tls-cert-valid | fail (self-signed) | fail (self-signed) |

| Check | bad-host | good-host |
|---|---|---|
| ports-exposed | fail (6379/redis) | pass |
````

- [ ] **Step 2: Generate certs, start the lab, and create the lab project with the CLI**

Run:
```bash
sh lab/gen-certs.sh
docker compose -f lab/docker-compose.yml up -d
npm run --silent dev -- init --dir lab/project --name secagent-lab --scan-label local-lab \
  --target bad-site=https://172.31.250.10,web,lab --target good-site=https://172.31.250.11,web,lab \
  --host bad-host=172.31.250.10,lab --host good-host=172.31.250.11,lab
```
Expected:
- `certificates written to lab/certs/`;
- both containers running (`docker compose -f lab/docker-compose.yml ps` shows 2 services up);
- `Created …/lab/project/.secagent`.

- [ ] **Step 3: Write the opt-in e2e test**

`test/lab.e2e.test.ts`:
```ts
import { cp, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanNoAi } from '../src/scan/no-ai.js';
import { tempDir } from './helpers/tmp.js';

const LAB_PROJECT = path.join(import.meta.dirname, '..', 'lab', 'project', '.secagent', 'project.yaml');

const EXPECTED: Array<[check: string, target: string, outcome: string]> = [
  ['http-redirect-https', 'bad-site', 'fail'],
  ['http-redirect-https', 'good-site', 'pass'],
  ...['hdr-hsts', 'hdr-csp', 'hdr-frame-options', 'hdr-content-type-options', 'hdr-referrer-policy', 'hdr-permissions-policy', 'hdr-x-powered-by', 'hdr-server-version', 'cookie-flags'].flatMap(
    (check): Array<[string, string, string]> => [
      [check, 'bad-site', 'fail'],
      [check, 'good-site', 'pass'],
    ],
  ),
  ['header-budget', 'bad-site', 'pass'],
  ['header-budget', 'good-site', 'pass'],
  ['exposed-paths', 'bad-site', 'fail'],
  ['exposed-paths', 'good-site', 'pass'],
  ['tls-no-legacy', 'bad-site', 'fail'],
  ['tls-no-legacy', 'good-site', 'pass'],
  ['tls-modern', 'bad-site', 'fail'],
  ['tls-modern', 'good-site', 'pass'],
  ['tls-cert-valid', 'bad-site', 'fail'],
  ['tls-cert-valid', 'good-site', 'fail'],
  ['ports-exposed', 'bad-host', 'fail'],
  ['ports-exposed', 'good-host', 'pass'],
];

describe.runIf(process.env.SECAGENT_LAB === '1')('lab end-to-end (start lab/docker-compose.yml first)', () => {
  it('produces the expected outcome for every seed check', async () => {
    const dir = await tempDir();
    await mkdir(path.join(dir, '.secagent'), { recursive: true });
    await cp(LAB_PROJECT, path.join(dir, '.secagent', 'project.yaml'));
    const record = await scanNoAi(dir);
    const actual = EXPECTED.map(([check, target]) => {
      const r = record.results.find((x) => x.check_id === check && x.target === target);
      return `${check}@${target}=${r?.outcome ?? 'missing'}`;
    });
    expect(actual).toEqual(EXPECTED.map(([check, target, outcome]) => `${check}@${target}=${outcome}`));

    const exposed = record.results.find((r) => r.check_id === 'exposed-paths' && r.target === 'bad-site');
    expect(exposed?.severity).toBe('critical');
    expect(exposed?.observed).toContain('/.env');
    expect(exposed?.observed).toContain('/.git/config');
    expect(exposed?.observed).toContain('/app.js.map');
  }, 120_000);
});
```

- [ ] **Step 4: Run the lab scan and the e2e test**

Run:
```bash
npm run --silent dev -- scan --no-ai --dir lab/project
SECAGENT_LAB=1 npx vitest run test/lab.e2e.test.ts
```
Expected:
- the CLI prints the scan summary with `CRITICAL open exposed-paths@bad-site` at the top, and `HIGH`/`MEDIUM`/`LOW` lines for the other bad-site findings;
- the e2e test PASSES (1 test).

If a row differs, compare the evidence file named in `.secagent/findings/latest.json` against the README table before changing any code.

- [ ] **Step 5: Run the full default suite (lab test skipped) and stop the lab**

Run:
```bash
npx vitest run && npx tsc -p tsconfig.json
docker compose -f lab/docker-compose.yml down
```
Expected: every test PASSES, with `lab.e2e.test.ts` reported as skipped; `tsc` exits 0; containers removed.

- [ ] **Step 6: Commit**

The lab project's own `.gitignore` keeps evidence and findings out of git, so only `project.yaml` and `knowledge/` are added.
```bash
git add lab/README.md lab/docker-compose.yml lab/gen-certs.sh lab/bad-site lab/good-site lab/project test/lab.e2e.test.ts
git status --short lab/project
git commit -m "test(lab): add bad/good nginx lab with opt-in end-to-end scan"
```
Expected from `git status --short lab/project`: only `.secagent/.gitignore`, `.secagent/project.yaml`, `.secagent/knowledge/notes.md` and `.secagent/knowledge/exceptions.yaml` are staged.

---

## Done when

- `npx vitest run` passes, with the lab test skipped by default; `SECAGENT_LAB=1` with the lab running also passes.
- `npx tsc -p tsconfig.json` is clean, and `npm run build` produces `dist/cli.js`.
- `secagent init` + `secagent scan --no-ai` work on any project, writing `.secagent/findings/latest.json`, history and evidence.
- Every network touch is scope-checked. Evidence contains no cookie values or exposed-file contents.
