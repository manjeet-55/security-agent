# Using secagent from an AI client (MCP)

`secagent mcp` lets an AI assistant (Claude Code, Cursor, any MCP client) run secagent's checks and read the results. secagent still does all the checking, deterministically and from evidence; the assistant explains the findings, helps you fix them, and re-scans to confirm.

## Set up

Set the project up once, in its folder: run `secagent` (the guided scan) or `secagent init`. Then point your client at the server.

Claude Code:

```bash
claude mcp add secagent -- secagent mcp --dir /path/to/your-project
```

Any client that takes a JSON config (`.mcp.json`, `.cursor/mcp.json`, and similar; check your client's docs for the file):

```json
{
  "mcpServers": {
    "secagent": {
      "command": "secagent",
      "args": ["mcp", "--dir", "/path/to/your-project"]
    }
  }
}
```

If `secagent` is not on your PATH (no `npm link`), use `"command": "node"` with `"args": ["/path/to/secagent/dist/cli.js", "mcp", "--dir", "/path/to/your-project"]`.

Then ask, for example: "Run a security scan of this project and tell me what to fix first", or "Is CVE-2024-6387 really a problem on web-1?"

## Tools

| Tool | What it does |
|---|---|
| `project_info` | The project, the websites and servers that can be probed, code settings, how old each server snapshot is, what a scan can run, and the last scan in one line |
| `run_scan` | Runs the checks (all, or `groups`: `code`, `web`, `host`), writes the Markdown and PDF report, returns the verdict and findings. Areas not re-run keep their earlier results and are marked `from_earlier_scan`. One scan at a time. |
| `get_findings` | Findings of the last scan with what was found, why it matters, the fix, a link and evidence ids; filter by `status` or `severity` |
| `get_report` | The latest report as Markdown, plus the PDF path |
| `get_evidence` | One evidence record by id |
| `verify_claim` | Is a third-party scanner's CVE claim true for a host? Uses the host snapshot and the distro's own advisories |
| `kb_search` | Keyword search over the knowledge base: lessons from past remediations (global and the project's own) and the check catalog. Hits say whether they are approved or pending review. |
| `kb_read` | One lesson or check by id; `INDEX` is the one-line-per-entry overview, `notes` the project's notes, `exceptions` its accepted risks |

## What the assistant can and cannot do

- It cannot change which websites or servers are probed. No tool edits `.secagent/project.yaml`; only you can.
- Every probe still goes through the scope guard, and websites on private addresses need `allow_private` in `project.yaml`.
- It never receives secret values. Findings carry file, line, pattern and a fingerprint; evidence leaves out page bodies. Tell it to have the credentials rotated, not to read them.
- `accepted_risk` means a person accepted the risk until a date; it is not fixed. The assistant cannot accept a risk: only a person running `secagent accept` or editing `exceptions.yaml` can.
- Knowledge marked pending can add a finding or raise a severity; only approved knowledge can back calling a finding a false positive or lowering its severity.
- Statuses come from the scan. The server tells the assistant that `unverifiable` means unknown, and that nothing is fixed until a new scan says so.
- A scan started this way is recorded as such, and the report says "Run by an AI assistant through the MCP server".

## Troubleshooting

- "No project config ... Run secagent init first": the `--dir` folder has no `.secagent/project.yaml`. Run `secagent` there.
- The client shows no tools: run `secagent mcp --dir <folder>` by hand. It should print nothing and wait; an error message means the folder or the install is wrong.
- Nothing is written to stdout except the protocol, so logs never corrupt the connection.

## Dependency note

The server uses `@modelcontextprotocol/sdk` 1.32.1 (exact pin). `npm audit` lists `body-parser` and `fast-uri` through it. Neither is reachable over stdio (the HTTP transport is not used, and `fast-uri` only validates a local client's tool arguments), and the patched releases were too new for the project's two-week rule when this was added. Add `overrides` for them after 2026-11-05.
