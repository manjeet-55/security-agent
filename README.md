# secagent

A security check you run from the terminal, inside the project it checks. It asks what it needs (deployed URLs, environment, servers), asks for your permission before it touches anything, scans, and writes a report anyone on the team can read, as Markdown and PDF.

It is deterministic: no AI model and no API key, and the same inputs give the same result. Your code, files and secrets never leave your machine. A scan sends requests to the websites and servers you list; the npm dependency check and the server checks look up package names and versions in public advisory databases (OSV, Ubuntu Security, CISA). (An AI assistant can drive it through MCP, see below; it still decides nothing.)

**New here?** [docs/usage.md](docs/usage.md) is the full guide: the workflow, how to scan code, websites and servers, every command and option, the report, and CI use.

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
- `.secagent/reports/latest.html` (one self-contained page, opens in any browser)

Run `secagent` again in the same folder to scan again, change the answers, or start over.

## What it checks

| Area | Checks |
|---|---|
| Code | secrets in source files (keys, tokens, private keys, passwords in URLs), `.env`/key/credential files committed or one `git add .` away from it, secrets that were committed once and removed since (git history), npm dependencies with known vulnerabilities (`package-lock.json` against OSV) |
| Websites and APIs | security headers, cookies, CORS, HTTP to HTTPS redirect, TLS versions and certificate, files that should not be served (`.env`, `.git`, source maps), DNS aliases pointing at names that no longer exist |
| Servers | SSH and nginx settings, listening database ports, pending security updates, packages with distro advisories (from the read-only collector's output; `distro_mirrors` vouches for a private apt mirror), answering directly behind a load balancer |

## What the report says

A verdict, what to fix first, and for every finding: what was found, why it matters, how to fix it (with advice for your stack), and a link to learn more. Checks that could not run are listed under "Could not verify" and are never counted as passed. Secret values are never printed, only the file, the line and a short fingerprint. A scan limited with `--only` marks the areas it did not re-check as coming from an earlier scan.

## Knowledge base

`knowledge/lessons/` holds short, sourced lessons from real remediations (for example: distro backports make version-banner CVE claims unreliable, a timeout from the wrong network proves nothing, third-party repositories are not covered by automatic updates). Each lesson is reviewed (`review: approved`) or not yet (`pending`). A project can add its own under `.secagent/knowledge/lessons/`, and records accepted risks in `.secagent/knowledge/exceptions.yaml` (owner, reason, expiry). An AI client reads them with `kb_search` and `kb_read`, and can propose new ones with `kb_write`: each must quote a page from an allowlisted reference site (`knowledge/sources.yaml`) word for word, and stays pending until a person approves it with `secagent kb review --approve <id> --by <name>` (or rejects it). `knowledge/INDEX.md` is the generated overview (`secagent kb index`).

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

Or install the Claude Code plugin, which adds the server and a `/security-review` command: `claude plugin marketplace add /path/to/secagent`, then `claude plugin install secagent@secagent`. The playbook AI clients follow is `agent/AGENTS.md`.

## Check that everything is set up

`secagent doctor` checks Node, git, the project, whether the scope is confirmed on this machine, server snapshot age, the last scan and whether the advisory database is reachable, and says how to fix whatever is wrong. `secagent mcp setup` prints the exact command that connects Claude Code (or a JSON config for another client) to this folder.

## Use it in CI

```bash
secagent scan --only code --fail-on high
```

prints the findings, writes the reports, and exits 1 when an open finding is high or critical. The repository's own workflow (`.github/workflows/ci.yml`) shows the typecheck, test and build steps.

## Commands for scripts and CI

`secagent` with no command only starts the guided scan on a terminal; elsewhere it prints this list.

| Command | What it does |
|---|---|
| `secagent start [--dir]` | The guided scan |
| `secagent init [--dir] [--target id=url,web\|api,env] [--host name=address,env]` | Create `.secagent/` and `project.yaml` without questions |
| `secagent scan [--only code\|web\|host] [--fail-on <severity>]` | Run the checks and write the reports; with `--fail-on`, exit 1 on an open finding at that severity or above |
| `secagent doctor` | Check the machine and project, with a fix for each problem |
| `secagent mcp setup` | Print the command that connects an AI client to this folder |
| `secagent report` | Re-render the report of the latest scan |
| `secagent collector --host <name>` | Print the read-only collector script for a server |
| `secagent snapshot add --host <name> <file>` | Store the collector's output |
| `secagent verify --host <name> --cve <id>` | Is a scanner's CVE claim true for this host? |
| `secagent learn` | Refresh CISA KEV and package advisories |
| `secagent mcp [--dir]` | Serve the project to an AI client over MCP (stdio) |
| `secagent accept <finding-id> --owner --reason --until` | Accept an open finding's risk until a date |
| `secagent kb review [--approve <id> --by <name>] [--reject <id>]` | List, approve or reject lessons an AI assistant proposed |
| `secagent kb index` | Regenerate `knowledge/INDEX.md` (maintainers) |

`.secagent/project.yaml` lists the only websites and servers secagent will touch; the code checks read the project folder and its git history.

## Scope and limits

What it does and does not do, so a clean report is read correctly:

- **It checks what you list.** Websites, APIs and servers go in `.secagent/project.yaml` (the guided scan writes it). Anything else is refused, redirects are not followed, and cloud-metadata addresses are never probed. It does not discover other sites, subdomains or endpoints by itself.
- **It is read-only.** `GET`/`HEAD` requests, TLS handshakes and TCP connection tests. No logins, no guessing, no injection or fuzzing tests, so it does not test authorisation or business logic.
- **Hosting is irrelevant for websites and APIs.** EC2, Vercel, Netlify or on-premises: list the public URL.
- **Dependency scanning is npm only** (`package-lock.json`). Other ecosystems are not checked yet.
- **Server package advisories cover Ubuntu and Debian only.** Amazon Linux and other systems report those checks as "could not verify" (see [docs/usage.md](docs/usage.md#scanning-a-server)).
- **Server checks need a snapshot** a person collects with the read-only collector; secagent never logs in. Snapshots older than 7 days are marked stale.
- **A clean report means "no issue found by these checks".** Checks that could not run are listed apart and never counted as passed.

## Responsible use

Scan only systems you own or have written permission to test. secagent asks for that confirmation before it touches any website or server and records it on your machine, and its requests carry a `secagent` user agent so the owner can recognise them. It is a self-assessment tool, not a penetration-testing or exploitation tool.

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

The `secagent` command (after `npm link`) runs the built files in `dist/`, not the sources. After changing the code or pulling new commits, run `npm run build` (or `npm install`, which builds too), or new commands will answer "Unknown command". `npm run dev -- <command>` runs the sources directly.

The design is in `docs/superpowers/specs/`: `2026-10-29-secagent-guided-agent-design.md` for the guided scan and reports, `2026-10-28-secagent-design.md` for the checks. Working on the code with an AI assistant: start from [AGENTS.md](AGENTS.md) (also `CLAUDE.md`).

## License

[MIT](LICENSE).
