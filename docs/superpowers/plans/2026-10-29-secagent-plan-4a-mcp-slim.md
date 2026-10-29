# secagent Plan 4a: Slim MCP Server

> For agentic workers: execute task by task, test first. Spec: `docs/superpowers/specs/2026-10-29-secagent-mcp-slim-design.md`.

**Goal:** `secagent mcp` serves six tools over stdio on top of the existing engine.
**Architecture:** `src/mcp/server.ts` builds an `McpServer` with tools registered from `src/mcp/tools/*.ts`; a small `src/mcp/state.ts` holds the project dir, injected dependencies (net, advisories, clock) and a scan lock. Tests link a real SDK client to the server in memory (`test/helpers/mcp.ts`).
**Tech:** `@modelcontextprotocol/sdk` 1.32.1 (`McpServer.registerTool`, `StdioServerTransport`, `InMemoryTransport`), zod 4.

## Global Constraints
- Node >=20.19. No other new dependency. Never run a formatter. No AI attribution or Co-Authored-By in commits. Explicit `git add`.
- Fail-closed, secrets never in results, nothing on stdout but the protocol.
- Every task ends with `npx vitest run` and `npx tsc -p tsconfig.json` green.

## Files
Create `src/mcp/state.ts`, `result.ts`, `server.ts`, `tools/project.ts`, `tools/scan.ts`, `tools/read.ts`, `tools/verify.ts`; `test/helpers/mcp.ts`; `test/mcp/*.test.ts`; `docs/mcp.md`. Modify `src/cli.ts` (`mcp`), `src/findings/schema.ts` (`trigger`), `src/scan/no-ai.ts` (`trigger` dep), `src/report/model.ts`, `README.md`.

### Task 1: skeleton, `project_info`, `trigger`, `secagent mcp`
Interfaces:
```ts
// src/mcp/state.ts
export interface ServerOptions { projectDir: string; now?: () => Date; net?: NetClient; advisories?: Advisories; checksDir?: string }
export class ServerState { constructor(readonly opts: ServerOptions); scanning: boolean }
// src/mcp/result.ts
export function jsonResult(value: unknown): CallToolResult;      // one text block, JSON
export function errorResult(message: string): CallToolResult;     // isError: true
export async function guarded(fn: () => Promise<CallToolResult>): Promise<CallToolResult>; // known errors -> errorResult
// src/mcp/server.ts
export const SERVER_INSTRUCTIONS: string;
export function createMcpServer(opts: ServerOptions): { server: McpServer; state: ServerState };
export async function runMcpStdio(opts: ServerOptions): Promise<void>;
```
Tests: lists the tools registered so far; `project_info` returns the project, groups, `last_scan: null` before a scan, snapshot age per host; an invalid project.yaml is an error result; instructions contain the five rules; `trigger` accepted by the record schema and `mcp` changes the report's About line.
Steps: failing tests, implement, `secagent mcp [--dir]` in the CLI (USAGE line), green, commit `feat(mcp): MCP server skeleton with project_info, secagent mcp`.

### Task 2: scan and read tools
- `run_scan({groups?})`: `scanNoAi(dir, { only, trigger: 'mcp', now, net, advisories, checksDir })`, then `loadReportInput` + `writeReport(md, pdf)`; returns `{ verdict, counts, findings, diff, report: { markdown, pdf } }` with compact findings `{ id, severity, status, title, where, observed }`. Sets `state.scanning`; a concurrent call returns an error result. Code group with `code.enabled: false` returns an error result saying so.
- `get_findings({status?, severity?})`: from `FindingsStore.latest()`; none yet → error result "No scan yet: call run_scan first". Findings include `fix` text and `evidence`.
- `get_report()`: the latest `.md` text and the PDF path; none yet → same error.
- `get_evidence({id})`: `EvidenceStore.get`; invalid id or missing file → error result; for `kind: 'http'` data, `bodySnippet` replaced by `"[omitted]"` (recursively for `data.obs`-style nesting is not needed: the stored data is the observation itself).
Tests: scan over a leaky repo; `groups` filter; concurrent scan refused; secrets never in any result (planted fakes); partial scan keeps others (labelled); filters; evidence body omitted; no-scan errors; the tools do not exist for writing project.yaml (the tool list has exactly the six names).
Commit `feat(mcp): run_scan, get_findings, get_report and get_evidence`.

### Task 3: `verify_claim`, stdio end-to-end, docs
- `verify_claim({host, cve, package?})`: `Scope.host`, `verifyClaim({host, snapshots, advisories, evidence, now}, {cve, package})` → `jsonResult(result)`; bad CVE id → error result.
- End-to-end: spawn `tsx src/cli.ts mcp --dir <tmp project>` as a child with the SDK `StdioClientTransport`, initialise, list tools, call `project_info` and `run_scan {groups:['code']}`; assert the server's stdout was clean (the client parsed every message) and stderr empty.
- `docs/mcp.md`: setup for Claude Code (`claude mcp add secagent -- secagent mcp --dir <project>`), a generic `.mcp.json`, the six tools, the safety rules, the audit note. README gets a short "Use it from an AI client" section.
Commit `feat(mcp): verify_claim, stdio end-to-end test, MCP docs`.

## Done when
All three tasks committed, suite and tsc green, `npm run build` output `node dist/cli.js mcp` answers `initialize` over stdio, ledger updated.
