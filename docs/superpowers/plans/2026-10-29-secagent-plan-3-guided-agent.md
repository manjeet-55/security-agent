# secagent Plan 3: Guided Agent Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Running `secagent` in a project folder asks for what it needs, asks for consent, scans with live progress and writes a Markdown and PDF report a non-specialist can read.

**Architecture:** A deterministic wizard (`src/wizard/`) on a small prompt layer (`src/ui/`) drives the existing engine (`initProject`, `scanNoAi`). A report block model (`src/report/model.ts`) feeds two renderers, Markdown and PDF, so both always say the same thing. Spec: `docs/superpowers/specs/2026-10-29-secagent-guided-agent-design.md`.

**Tech Stack:** TypeScript (ESM, Node >=20.19), vitest, zod 4, yaml, `node:readline` for prompts, `pdfkit` 0.20.2 for PDF.

**Budget note (owner):** tokens are tight. Tasks pin interfaces, files and test cases exactly; the code is written once, in the task's commit, test first. No per-task reviewer loop; one final review at the end.

## Global Constraints

- Node `>=20.19` (do not raise). ESM, `.js` import suffixes.
- The only new runtime dependency is `pdfkit` at exactly `0.20.2`, installed with `npm install --save-exact --before=2026-10-15 pdfkit@0.20.2`. Its types, `@types/pdfkit`, are an exact-pinned devDependency installed the same way.
- Never run a formatter. Match the surrounding code's style and comment density.
- No AI attribution and no Co-Authored-By lines in commits. Commits go on `main`, with an explicit `git add` of the files.
- Fail-closed: no evidence means unverifiable, never pass. The report keeps *Could not verify* apart from *Passed*.
- No probe without consent. When any URL or server is in scope, the wizard needs an explicit yes before saving or probing.
- Secret values never appear in results, reports, console output or files. Only path, line, pattern and fingerprint.
- No real-looking tokens in the repository. Fakes are built by string concatenation (`test/helpers/secrets.ts`).
- Every task ends with `npx vitest run` and `npx tsc -p tsconfig.json` green.

## File Structure

| File | Responsibility |
|---|---|
| `src/report/model.ts` | `Block` types, `verdict()`, `buildReport()`, `loadReportInput()` |
| `src/report/markdown.ts` | `renderMarkdown(blocks)` |
| `src/report/pdf.ts` | `renderPdf(blocks, opts)` with pdfkit |
| `src/report/write.ts` | `writeReport()`: timestamped dir plus `latest.*` copies |
| `src/ui/style.ts` | ANSI colours and symbols, honouring TTY and `NO_COLOR` |
| `src/ui/prompt.ts` | `Prompter` interface, `PromptCancelled`, `createTtyPrompter()` |
| `src/wizard/questions.ts` | `askPlan()`: questions to `WizardPlan`, writes nothing |
| `src/wizard/run.ts` | `runWizard()`: save, scan with progress, report, result screen |
| `scripts/demo-setup.ts`, `scripts/demo-server.ts` | Demo kit |
| `test/helpers/prompter.ts` | `ScriptedPrompter` |
| Modify `src/findings/schema.ts` | `ScanRecord.consent_at?` |
| Modify `src/checks/catalog.ts` | `CheckInstance.why?` |
| Modify `src/scan/no-ai.ts` | `onPlan`, `onResult`, `consentAt` |
| Modify `src/host/store.ts` | `parseSnapshotText()` split out of `SnapshotStore.add` |
| Modify `src/cli.ts` | `report`, `start`, bare `secagent`, report after `scan --no-ai` |
| Modify `knowledge/checks/*.yaml` | `why:` on all 29 seeds |

---

### Task 1: Report model, Markdown, `secagent report`, report after `scan --no-ai`

**Files:**
- Create: `src/report/model.ts`, `src/report/markdown.ts`, `src/report/write.ts`
- Modify: `src/findings/schema.ts` (add `consent_at: z.iso.datetime().optional()` to `ScanRecordSchema`), `src/scan/no-ai.ts` (`ScanDeps.consentAt?: Date`, written as `consent_at`), `src/cli.ts` (`report` command; `scan --no-ai` writes the Markdown report and prints its path)
- Test: `test/report/model.test.ts`, `test/report/markdown.test.ts`, `test/report/write.test.ts`, `test/cli.test.ts`

**Interfaces:**
- Consumes: `ScanRecord`, `Finding`, `CheckResult` (`src/findings/schema.ts`, `src/types.ts`); `CheckInstance`, `loadCheckInstances` (`src/checks/catalog.ts`); `CHECK_TYPES`; `GLOBAL_CHECKS_DIR`, `projectStateDir`; `FindingsStore`; `loadProject`; `resultKey`; `SEVERITY_RANK`.
- Produces:

```ts
// src/report/model.ts
export type Tone = 'red' | 'yellow' | 'green';
export type Span = { text: string; bold?: boolean; code?: boolean; href?: string };
export type Block =
  | { kind: 'title'; text: string; meta: string }
  | { kind: 'verdict'; tone: Tone; text: string }
  | { kind: 'heading'; level: 2 | 3; text: string; severity?: Severity }
  | { kind: 'paragraph'; spans: Span[] }
  | { kind: 'fields'; items: Array<{ label: string; spans: Span[] }> }
  | { kind: 'list'; items: Span[][] }
  | { kind: 'table'; head: string[]; rows: string[][] };
export type Area = 'code' | 'web' | 'host';
export const AREA_LABEL: Record<Area, string>; // Code | Websites and APIs | Servers
export interface ReportInput { project: ProjectConfig; record: ScanRecord; instances: ReadonlyMap<string, CheckInstance> }
export function verdict(record: ScanRecord): { tone: Tone; text: string };
export function areaOf(instance: CheckInstance | undefined): Area; // applies_to code → code, host → host, else web
export function whereOf(project: ProjectConfig, target: string): string; // URL, "name (address)" or "this project's code"
export function buildReport(input: ReportInput): Block[];
export async function loadReportInput(projectDir: string, deps?: { checksDir?: string }): Promise<ReportInput | undefined>; // undefined: no scan yet
// src/report/markdown.ts
export function renderMarkdown(blocks: readonly Block[]): string;
// src/report/write.ts
export type ReportFormat = 'md' | 'pdf';
export async function writeReport(projectDir: string, input: ReportInput, opts: { formats: readonly ReportFormat[] }): Promise<{ files: string[]; latest: string[] }>;
```

Verdict rules (exact text): open critical or high → red `Needs attention: <n> high-priority issue(s)` (critical and high are counted together); otherwise any open → yellow `Some issues to fix: <n> open`; otherwise any unverifiable finding → yellow `No issues found, but <n> check(s) could not be verified`; otherwise green `No issues found`.

Section order, from spec §5: title, verdict, `## At a glance` (table Area | Checks | Issues | Could not check, areas with results only), `## Fix first` (up to 5 open findings, severity then id: bold title, ` — ` where, ` — ` first line of `fix.how`), `## Findings` (`### <SEVERITY>: <title>` plus fields Where / What we found / Why it matters / How to fix / Learn more / Evidence), `## Could not verify` (table Check | Where | Reason, then "These are not passes: fix the cause and scan again."), `## Fixed since the last scan` (only when `diff.fixed` is not empty), `## Passed` (one list item per area: `<Area>: title, title, ...`), `## About this scan` (scope list, consent line, method, fail-closed line, secrets line). *Why it matters* uses `instance.why` when present, otherwise the title. Empty sections are omitted, apart from Findings, which says "No open findings." when it has none.

- [ ] **Step 1: Write failing tests.** `model.test.ts`, with a hand-built `ScanRecord` (one open high code finding, one open medium web finding, one unverifiable host finding, a pass on each area, one id in `diff.fixed`):
  - verdict for all four cases;
  - `areaOf` and `whereOf`;
  - the order of section headings;
  - Fix first ordering;
  - the Could not verify table rows;
  - the consent line with and without `consent_at`;
  - Passed grouping.
  `markdown.test.ts`: each block kind renders (`# title`, `> **verdict**`, `### HIGH: ...`, `- **What we found:** ...`, a GFM table escaping `|`, `code` spans in backticks). `write.test.ts`: the files land in `.secagent/reports/<YYYYMMDD-HHMMSS>/report.md`, `latest.md` is identical, and `loadReportInput` returns `undefined` before any scan.
- [ ] **Step 2: Run** `npx vitest run test/report` and expect FAIL (modules missing).
- [ ] **Step 3: Implement** `model.ts`, `markdown.ts`, `write.ts` (formats `md` only until Task 3; passing `pdf` throws `Error('pdf rendering arrives in Task 3')` until then), the schema field and `consentAt`.
- [ ] **Step 4: CLI.** Test first in `test/cli.test.ts`:
  - `scan --no-ai` prints `Report: <abs path>/.secagent/reports/latest.md`;
  - `report` re-renders it;
  - `report` before any scan exits 1 with `No scan yet: run secagent scan --no-ai first`.
  Implement, adding `report    Re-render the latest report (Markdown and PDF)` to USAGE.
- [ ] **Step 5: Extend the no-leak test** (`test/code/no-leak.test.ts`). `filesUnder(.secagent)` already covers `reports/`. Assert that `latest.md` exists, so the check is not vacuous.
- [ ] **Step 6:** Full suite and tsc green. Commit `feat(report): Markdown report from a block model, secagent report`.

### Task 2: `why` on every check

**Files:** Modify `src/checks/catalog.ts` (`why: z.string().min(1).optional()` in `CheckInstanceSchema`) and all 29 `knowledge/checks/*.yaml`. Test: `test/checks/catalog.test.ts`, `test/report/model.test.ts`.

- [ ] **Step 1: Failing tests.**
  - Every instance loaded from `GLOBAL_CHECKS_DIR` has a `why` of 20 to 300 characters, without the words "secagent" or "check".
  - A report finding uses `why`.
- [ ] **Step 2: Run** and expect FAIL.
- [ ] **Step 3: Add the field and write the texts.** One or two plain sentences on the harm, for a non-specialist. Example for `hdr-hsts`: "Without HSTS a browser can be tricked into loading the site over plain HTTP, where anyone on the same network can read or change the traffic."
- [ ] **Step 4:** Suite green. Commit `feat(checks): plain-language why for every seed check`.

### Task 3: PDF renderer

**Files:** Create `src/report/pdf.ts`. Modify `src/report/write.ts` (format `pdf`), `src/cli.ts` (the `report` and `scan --no-ai` output lists the PDF too), `package.json`/`package-lock.json` (install per Global Constraints). Test: `test/report/pdf.test.ts`, `test/report/write.test.ts`.

**Interfaces:**
```ts
// src/report/pdf.ts
export interface PdfOptions { title: string; footer: string; createdAt: Date }
export function renderPdf(blocks: readonly Block[], opts: PdfOptions): Promise<Buffer>;
```
Layout:
- A4, 50 pt margins.
- Helvetica 10 pt body, Helvetica-Bold for headings and labels.
- Title 20 pt; verdict in a filled box: red `#b42318`, yellow `#b54708`, green `#067647`, white text.
- Severity label colours: critical `#7a271a`, high `#b42318`, medium `#b54708`, low `#175cd3`, info `#475467`.
- Tables: a header row on light grey; cell heights from `doc.heightOfString`; a new page, with the header repeated, when a row does not fit.
- `bufferPages: true`; the footer `"<footer> · page n of m"` is drawn on every page at the end.
- `info: { Title, Creator: 'secagent', CreationDate: createdAt }`.

- [ ] **Step 1: Failing tests.**
  - The buffer starts with `%PDF-`.
  - It ends with `%%EOF` (after trimming).
  - The page count (`/Type /Page` occurrences, not `/Pages`) is 1 or more.
  - A report with 60 findings produces more than 1 page.
  - `writeReport` with `['md','pdf']` writes both, plus `latest.pdf`.
- [ ] **Step 2: Run** and expect FAIL.
- [ ] **Step 3: Install pdfkit, then implement.**
- [ ] **Step 4:** Suite and tsc green. Generate one PDF from a fixture into the scratchpad and open it (Read tool) to eyeball the layout. Commit `feat(report): PDF report with pdfkit`.

### Task 4: Prompt layer

**Files:** Create `src/ui/style.ts`, `src/ui/prompt.ts`, `test/helpers/prompter.ts`. Test: `test/ui/prompt.test.ts`, `test/ui/style.test.ts`.

**Interfaces:**
```ts
// src/ui/style.ts
export interface Style { enabled: boolean; red(s: string): string; yellow(s: string): string; green(s: string): string; cyan(s: string): string; dim(s: string): string; bold(s: string): string }
export function createStyle(stream: { isTTY?: boolean }, env?: NodeJS.ProcessEnv): Style; // off without a TTY or with NO_COLOR set
export const SYMBOL: { pass: string; fail: string; unverifiable: string; error: string; pointer: string; on: string; off: string }; // ✓ ✗ ? ! › ◉ ○
// src/ui/prompt.ts
export interface Choice<T> { value: T; label: string; hint?: string }
export interface Prompter {
  text(q: { message: string; default?: string; validate?: (value: string) => string | undefined }): Promise<string>;
  confirm(q: { message: string; default?: boolean }): Promise<boolean>;
  select<T>(q: { message: string; choices: readonly Choice<T>[]; default?: T }): Promise<T>;
  multiselect<T>(q: { message: string; choices: readonly Choice<T>[]; initial?: readonly T[]; min?: number }): Promise<T[]>;
  note(text: string): void;
}
export class PromptCancelled extends Error {}
export function createTtyPrompter(input: NodeJS.ReadableStream & { isTTY?: boolean; setRawMode?(on: boolean): unknown }, output: NodeJS.WritableStream, style: Style): Prompter;
// test/helpers/prompter.ts
export class ScriptedPrompter implements Prompter { constructor(answers: unknown[]); readonly asked: string[]; readonly notes: string[]; done(): void /* throws if answers are left over */ }
```
Behaviour:
- `text` reads one line. An empty line takes `default`. When `validate` returns a message, it is shown and the question is asked again.
- `confirm` accepts y, yes, n, no (any case); an empty line takes the default.
- `select` and `multiselect` use raw mode: up and down move, space toggles (multiselect), enter accepts. `multiselect` refuses fewer than `min` choices with an inline message.
- Ctrl+C (`\u0003`) or the end of input rejects with `PromptCancelled`, and raw mode is restored on every exit path.
- Without raw mode (no `setRawMode`), selects fall back to a numbered list read as a line.
- `ScriptedPrompter` throws `Error('unexpected question: <message>')` when it runs out of answers, and records every message in `asked`.

- [ ] **Step 1: Failing tests.** Drive `createTtyPrompter` with a `PassThrough` that has `isTTY` and a `setRawMode` spy:
  - text: default, and validate then retry;
  - confirm: default, and y/n;
  - select: arrow down then enter;
  - multiselect: space toggle and min;
  - Ctrl+C rejects and calls `setRawMode(false)`;
  - the numbered fallback without raw mode;
  - style is off with `NO_COLOR` and off without a TTY.
- [ ] **Step 2: Run** and expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Green. Commit `feat(ui): terminal prompts without dependencies`.

### Task 5: Wizard questions

**Files:** Create `src/wizard/questions.ts`. Modify `src/host/store.ts` (export `parseSnapshotText(text: string, now: Date): Snapshot`, used by `add`). Test: `test/wizard/questions.test.ts`.

**Interfaces:**
```ts
// src/wizard/questions.ts
export interface WizardPlan {
  config: ProjectConfig;            // validated; written by runWizard, not here
  groups: ScanGroup[];              // what to scan this run
  consentAt?: Date;                 // set when any target or host is in scope
  snapshots: Array<{ host: string; text: string }>; // validated collector output to store on save
}
export interface AskDeps {
  dir: string;
  existing?: ProjectConfig;
  detection: StackDetection;
  now: () => Date;
  /** DNS lookup for the private-address question; injectable for tests. */
  resolve?: (hostname: string) => Promise<string[]>;
  readFile?: (file: string) => Promise<string>;
  writeCollector?: (host: string) => Promise<string>; // returns the path written
}
export async function askPlan(p: Prompter, deps: AskDeps): Promise<WizardPlan | undefined>; // undefined: user backed out
export function targetIdFor(url: string, taken: ReadonlySet<string>): string; // portal.example.com → portal-example-com, -2 on clash
```
The flow and the exact wording of each question follow spec §3, steps 1 to 6. With `existing` set, the first question is the select *Scan again with these settings* / *Change settings* / *Start over*. *Scan again* asks only for consent (when needed). Consent declined offers the select *Go back* / *Scan only the code* / *Quit*.

- [ ] **Step 1: Failing tests** (ScriptedPrompter, `resolve` stubbed):
  - code only: no consent asked, `groups == ['code']`, scan label `local`;
  - one web target: id derived, env `prod`, consent yes, `consentAt` set;
  - an invalid URL is re-asked;
  - a private IP is declined (URL dropped), then accepted (`allow_private: true`);
  - consent declined, then *Scan only the code*;
  - existing project, *Scan again*: two questions only;
  - existing project, *Change settings*: defaults pre-filled;
  - a server with a snapshot path that is invalid JSON is re-asked, then skipped;
  - `targetIdFor` clash.
- [ ] **Step 2: Run** and expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Green. Commit `feat(wizard): questions that build the project settings`.

### Task 6: Wizard run, `secagent start`, bare `secagent`

**Files:** Create `src/wizard/run.ts`. Modify `src/scan/no-ai.ts` (`onPlan?(total: number)`, `onResult?(r: CheckResult, area: Area)`), `src/cli.ts`. Test: `test/wizard/run.test.ts`, `test/cli.test.ts`, `test/scan/no-ai.test.ts`.

**Interfaces:**
```ts
// src/wizard/run.ts
export interface WizardDeps {
  prompter: Prompter; out: NodeJS.WritableStream; style: Style;
  now?: () => Date; net?: NetClient; advisories?: Advisories;
  openFile?: (file: string) => Promise<boolean>; // default: spawn xdg-open/open/start, detached, arg array
}
export async function runWizard(dir: string, deps: WizardDeps): Promise<number>; // 0 done, 130 cancelled, 1 known error
```
Steps:
1. `askPlan`.
2. Save: `initProject`, `saveProject(plan.config)`, store snapshots.
3. `scanNoAi` with `only: plan.groups`, `consentAt`, and progress lines `  ✓ <title>  <where>` grouped under `Code` / `Websites and APIs` / `Servers` headers, with a running `n/total`.
4. `writeReport` md and pdf.
5. Result screen: the coloured verdict, open counts by severity, the top 3 Fix first lines, both report paths.
6. The select *Open the report* / *Scan again* / *Exit*.

`PromptCancelled` returns 130. `ProjectConfigError`, `ScopeError` and `CatalogError` print their message and return 1.

CLI:
- `main([])` on a TTY (stdin and stdout) runs `runWizard(process.cwd(), ...)`; otherwise it prints USAGE (unchanged behaviour).
- `start [--dir]` runs the wizard, or without a TTY exits 1 with the spec §3 message.
- `CliDeps` gains `tty?: boolean` and `prompter?: Prompter` for tests.
- USAGE gets `start   Guided scan: asks what to check, then scans and writes the report (default when run with no command)`.

- [ ] **Step 1: Failing tests.**
  - `scanNoAi` calls `onPlan` once with the right total, and `onResult` once per result.
  - `runWizard` code-only on a leaky repo: output has `✗`, a `Needs attention` verdict and both report paths; `latest.pdf` exists; ScriptedPrompter done.
  - Web target against `startHttps` with consent: progress lists the web checks.
  - Cancel at the first question: 130 and no `project.yaml`.
  - CLI: `main([])` with `tty: false` prints usage; `start` with `tty: false` exits 1 with the message.
- [ ] **Step 2: Run** and expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Green. Then a manual check in a real terminal with `npx tsx src/cli.ts start --dir <scratch repo>`: arrow keys work, colours show, Ctrl+C restores the terminal. Commit `feat(wizard): guided scan with live progress, secagent start`.

### Task 7 (cuttable): Demo kit

**Files:** Create `scripts/demo-setup.ts`, `scripts/demo-server.ts`. Modify `package.json` (`"demo:setup": "tsx scripts/demo-setup.ts"`, `"demo:server": "tsx scripts/demo-server.ts"`). Test: `test/demo.test.ts`.

**Interfaces:**
```ts
// scripts/demo-setup.ts
export async function createDemoProject(dir: string): Promise<void>; // CLI: tsx scripts/demo-setup.ts <dir>
// scripts/demo-server.ts
export function startDemoServer(port?: number): Promise<{ url: string; close(): Promise<void> }>; // 127.0.0.1, default 8080
```
The demo project:
- `package.json` (express);
- `src/config.js` with a fake AWS key and a fake Stripe live key built by concatenation at setup time;
- a tracked `.env`;
- a commit that adds `deploy/key.txt` with a fake GitHub token, then a commit that removes it;
- an untracked `server.key`.
The server sends no security headers, answers `/.env` with `API_KEY=demo-value`, and sets one cookie without flags.

- [ ] **Step 1: Failing tests.**
  - After `createDemoProject`, a `scanNoAi --only code` finds all four code findings open.
  - `startDemoServer(0)` answers `/` without HSTS and `/.env` with `KEY=value` lines.
- [ ] **Step 2: Run** and expect FAIL.
- [ ] **Step 3: Implement.**
- [ ] **Step 4:** Green. Rehearse the full demo once by hand.
- [ ] **Step 5:** Commit `feat(demo): sample project and weak local server for demos`. Add the demo steps to `.superpowers/sdd/handoff.md`.

## Done when

- `secagent` in a project folder runs the whole flow on a real terminal and produces `latest.md` and `latest.pdf`.
- The suite and tsc are green, and the no-leak test covers the reports.
- Spec §3–§8 each map to a task above, and progress.md records each commit.
