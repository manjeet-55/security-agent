# secagent: Slim MCP Server Design

Date: 2026-10-29. Approved by the owner in conversation. Amends the main spec §9.3 (MCP tools): this is the first, small slice of it. The knowledge base, learning loop, `probe_http`, collector tools and playbook prompts stay in Plan 4b.

## 1. Goal

`secagent mcp [--dir <project>]` serves the existing engine over MCP on stdio, so any MCP client (Claude Code, Cursor, others) can run the same deterministic scan, read findings and the report, and judge a scanner's CVE claim. The AI client explains and prioritises; secagent decides every status from evidence.

## 2. Tools

| Tool | Input | Returns |
|---|---|---|
| `project_info` | none | name, stack, network label, targets and hosts from `project.yaml` (the only systems that can be probed), `code` settings, last scan time, snapshot age per host, the groups a scan can run |
| `run_scan` | `groups?: ('code'\|'web'\|'host')[]` | verdict, counts by severity and status, findings (compact), report paths, diff vs the previous scan. Writes the Markdown and PDF report like the CLI. Not reentrant: a second call while one runs is an error result. |
| `get_findings` | `status?`, `severity?` | findings from the last scan: id, severity, status, title, where, what was found, fix, evidence ids |
| `get_evidence` | `id` | one evidence record. HTTP evidence loses its `bodySnippet`. |
| `get_report` | none | the latest Markdown report as text, and the PDF path |
| `verify_claim` | `host`, `cve`, `package?` | the existing deterministic verdict (`not_affected`, `vulnerable`, ...) with its evidence id |

Read-only tools carry `readOnlyHint`; `run_scan` and `verify_claim` do not (they write evidence and reports inside `.secagent/`).

## 3. Rules (each tested)

- No tool writes `project.yaml`. Scope only changes when a person edits it; every probe still passes the scope guard.
- A failure (`ProjectConfigError`, `ScopeError`, `ObservationError`, invalid input, a scan already running) is an error result with a plain message, never a protocol crash.
- stdout carries the protocol only; nothing else prints there.
- Secret values never appear in a result: findings and code evidence hold path, line, pattern id and fingerprint only.
- The scan record gets an optional `trigger` (`wizard`, `cli`, `mcp`). The report's "About this scan" says for `mcp`: "Run by an AI assistant through the MCP server, for the websites and servers listed in project.yaml." (`wizard` keeps the consent line, `cli` or absent keeps "Run from the command line.")
- The server's `instructions` tell the client: call `run_scan` before saying anything about the project's state; a finding is open, fixed or unverifiable only as the scan says; `unverifiable` means unknown, not safe; never claim a fix without a new scan; never ask for or print secret values.

## 4. Dependency

`@modelcontextprotocol/sdk` 1.32.1, exact pin, installed with `--before=2026-10-15` (the newest release older than two weeks). `zod` stays a single 4.6.7. `npm audit` reports `body-parser` (high) and `fast-uri` (moderate), both transitive and both already patched upstream on 2026-10-19 and 2026-10-22, which is younger than the pin rule allows until early November. Accepted until then: the server uses stdio only, so the HTTP transport (and so `body-parser` through `express`) is never loaded, and `fast-uri` is reached only through schema validation of a local client's tool arguments. Add `overrides` after 2026-11-05.

## 5. Delivery

1. Skeleton: SDK, `createMcpServer`, `project_info`, `trigger` on the record, `secagent mcp`.
2. `run_scan`, `get_findings`, `get_report`, `get_evidence`.
3. `verify_claim`, a real stdio end-to-end test, `docs/mcp.md`, README section.
