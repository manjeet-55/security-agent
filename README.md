# secagent

A security check you run from the terminal, inside the project it checks. It asks what it needs (deployed URLs, environment, servers), asks for your permission before it touches anything, scans, and writes a report anyone on the team can read, as Markdown and PDF.

It is deterministic: no AI model, no API key, no data sent anywhere. The same inputs give the same result. (An AI assistant can drive it through MCP, see below; it still decides nothing.)

## Install

Needs Node 20.19 or newer.

```bash
npm install
npm run build
npm link        # puts the `secagent` command on your PATH
```

## Use it

```bash
cd your-project
secagent
```

It looks at the folder, then asks:

1. What to check: your code, deployed websites or APIs, servers.
2. For each website: its address, whether it is a website or an API, and the environment. For each server: a name, an address and the environment.
3. Which network you are scanning from (office, home, VPN). This is written on every piece of evidence.
4. Whether you own these systems or have written permission to test them. Nothing is probed without a yes.

Then it scans with one line per check, shows the verdict and the first three things to fix, and writes the report:

- `.secagent/reports/latest.pdf`
- `.secagent/reports/latest.md`

Run `secagent` again in the same folder to scan again, change the answers, or start over.

## What it checks

| Area | Checks |
|---|---|
| Code | secrets in source files (keys, tokens, private keys, passwords in URLs), `.env`/key/credential files committed or one `git add .` away from it, secrets that were committed once and removed since (git history) |
| Websites and APIs | security headers, cookies, HTTP to HTTPS redirect, TLS versions and certificate, files that should not be served (`.env`, `.git`, source maps) |
| Servers | SSH and nginx settings, listening database ports, pending security updates, packages with distro advisories (from the read-only collector's output) |

## What the report says

A verdict, what to fix first, and for every finding: what was found, why it matters, how to fix it (with advice for your stack), and a link to learn more. Checks that could not run are listed under "Could not verify" and are never counted as passed. Secret values are never printed, only the file, the line and a short fingerprint. A scan limited with `--only` marks the areas it did not re-check as coming from an earlier scan.

## Knowledge base

`knowledge/lessons/` holds short, sourced lessons from real remediations (for example: distro backports make version-banner CVE claims unreliable, a timeout from the wrong network proves nothing, third-party repositories are not covered by automatic updates). Each lesson is reviewed (`review: approved`) or not yet (`pending`). A project can add its own under `.secagent/knowledge/lessons/`, and records accepted risks in `.secagent/knowledge/exceptions.yaml` (owner, reason, expiry). An AI client reads them with `kb_search` and `kb_read`; `knowledge/INDEX.md` is the generated overview (`secagent kb index`).

## Accepting a risk

Some findings cannot be fixed today. A person can accept one for a limited time:

```bash
secagent accept hdr-csp@app --owner "Priya" --reason "CSP rolls out with the new proxy" --until 2026-12-15
```

It is written to `.secagent/knowledge/exceptions.yaml` (owner, reason, last day; at most a year ahead). The next scan reports that finding as an accepted risk in its own report section, and the verdict says so rather than "no issues". It counts as open again the day after the date passes, and only open findings can be accepted. An AI assistant cannot accept a risk for you.

## Use it from an AI client

`secagent mcp` serves the project to Claude Code, Cursor or any MCP client, so an assistant can run the scan, read the findings and report, and judge a scanner's CVE claim, while secagent stays the one that decides every status. The assistant cannot change what gets probed. Setup and details: `docs/mcp.md`.

```bash
claude mcp add secagent -- secagent mcp --dir /path/to/your-project
```

## Commands for scripts and CI

`secagent` with no command only starts the guided scan on a terminal; elsewhere it prints this list.

| Command | What it does |
|---|---|
| `secagent start [--dir]` | The guided scan |
| `secagent init [--dir] [--target id=url,web\|api,env] [--host name=address,env]` | Create `.secagent/` and `project.yaml` without questions |
| `secagent scan --no-ai [--only code\|web\|host]` | Run the checks and write the reports |
| `secagent report` | Re-render the report of the latest scan |
| `secagent collector --host <name>` | Print the read-only collector script for a server |
| `secagent snapshot add --host <name> <file>` | Store the collector's output |
| `secagent verify --host <name> --cve <id>` | Is a scanner's CVE claim true for this host? |
| `secagent learn` | Refresh CISA KEV and package advisories |
| `secagent mcp [--dir]` | Serve the project to an AI client over MCP (stdio) |
| `secagent accept <finding-id> --owner --reason --until` | Accept an open finding's risk until a date |
| `secagent kb index` | Regenerate `knowledge/INDEX.md` (maintainers) |

`.secagent/project.yaml` lists the only websites and servers secagent will touch; the code checks read the project folder and its git history.

## Try it with the demo

`docs/demo.md` is a five-minute script with a sample project that leaks in four ways and a deliberately weak local website:

```bash
npm run demo:setup -- ~/demo-shop
npm run demo:server          # in another terminal
cd ~/demo-shop && secagent
```

## Develop

```bash
npm test                 # vitest
npm run typecheck
```

The design is in `docs/superpowers/specs/`: `2026-10-29-secagent-guided-agent-design.md` for the guided scan and reports, `2026-10-28-secagent-design.md` for the checks.
