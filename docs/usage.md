# Using secagent

How to run secagent on a project, step by step, with every option. For why it is built this way, see [overview.md](overview.md); for AI-assistant setup, see [mcp.md](mcp.md).

## What it does, in one minute

secagent looks at your project the way an attacker's first pass would, then tells you in plain words what to fix first. It checks three areas:

| Area | What you give it | What it looks at |
|---|---|---|
| **Code** | nothing (it reads the project folder) | secrets in source, `.env`/key files committed or one `git add .` away, secrets removed from the code but still in git history, npm packages with known vulnerabilities |
| **Websites and APIs** | the deployed address (URL) | security headers, cookies, CORS, HTTP to HTTPS redirect, TLS versions and certificate, files and pages that should never be served (`.env`, `.git`, source maps, Spring Actuator, Apache server-status), DNS names pointing at services that no longer exist |
| **Servers** | an address, plus the output of a read-only script you run on the server | SSH and nginx settings, databases listening on all interfaces, pending security updates, packages with distro advisories, reachable admin/database ports, a server answering directly behind a load balancer |

It then writes one report (Markdown, PDF and HTML) with a verdict, the first things to fix, and for each finding what was found, why it matters, and how to fix it for your stack.

For everything a scanner cannot decide (routes without an auth guard, lookups without an ownership check, SQL built from strings, public buckets, CI pipelines), `secagent checklist` gives a **review checklist**: 49 rules saying what to look for in the code and configuration, how to decide, and how to fix it, for you or your AI assistant to work through. See [The review checklist](#the-review-checklist-what-the-scan-cannot-check).

What it will not do: log in anywhere, guess passwords, send anything but `GET`/`HEAD` requests and connection handshakes, follow redirects to other sites, or touch any address you did not list. Secret values are never printed, only file, line and a short fingerprint.

## The workflow

```
install  ->  secagent  ->  answer questions  ->  confirm permission  ->  scan  ->  report
                                                                                     |
              accept a risk  <-  fix  <-  read "fix first"  <------------------------+
                    |             |
                    +-- scan again (the report shows fixed, new, regressed) --> repeat
```

1. **Install** once (below) and check the setup with `secagent doctor`.
2. **Run `secagent` in the project folder.** It looks at the folder (stack, git) and asks what it needs.
3. **Confirm you may test the systems.** Nothing on the network is touched before this yes.
4. **Read the verdict and the first fixes.** The full report is in `.secagent/reports/`.
5. **Work through the review checklist** (`secagent checklist`, or `/security-review` in Claude Code) for what the scan cannot see.
6. **Fix, then run `secagent` again** and choose *Scan again*. A finding is fixed only when a new scan says so.
7. **Accept a risk** you cannot fix today, with an owner, a reason and an end date.
8. **Put the code checks in CI** so a leaked secret or vulnerable dependency fails the pull request.

## Install

Needs Node 20.19 or newer.

```bash
git clone https://github.com/manjeet-55/security-agent.git secagent
cd secagent
npm install          # also builds dist/
npm link             # puts the `secagent` command on your PATH
secagent doctor      # checks Node, git, the project, the advisory database; says how to fix each problem
```

Without `npm link`, replace `secagent` below with `node /path/to/secagent/dist/cli.js`. After pulling new commits, run `npm run build` again.

## The guided scan

```bash
cd your-project
secagent
```

It asks, in this order:

| Question | Notes |
|---|---|
| **Project name** | Defaults to the folder name. |
| **What should I check?** | Arrow keys move, **space ticks or unticks**, Enter confirms. "This project's code" is ticked by default; tick the others you want. |
| **Address of the deployed website or API** | It suggests addresses the project mentions (`homepage` in `package.json`, a `CNAME` file, public-URL keys such as `APP_URL` in `.env` files); nothing is probed from them. Private addresses (`10.x`, `192.168.x`, `127.0.0.1`, anything resolving to one) need an extra yes. |
| **Website or API? / Environment** | Environment is a label (prod, staging, dev, other) shown in the report. |
| **Add another?** | List every site and API you want checked, one per address. |
| **Where are you scanning from?** | Office, home, VPN, cloud/CI. Written on every piece of evidence, because a result from the wrong network proves little (a timeout from outside the allowlist is not "fixed"). |
| **Servers** | Name, address, environment. It prints the one-line command for the read-only collector and can write the script for you (see [Scanning a server](#scanning-a-server)). |
| **Permission** | "I own these systems or have written permission to test them." |

If you say no to permission, it offers to go back and change the answers, scan only the code, or quit.

Then it scans with one line per check (`✓` passed, `✗` failed, `?` could not verify), shows the verdict and the first things to fix, and opens the home screen. Before the questions you can choose **How secagent works first** to read the guides.

## The home screen

Every later run of `secagent` in the folder opens the home screen directly. It reads only local files:

```
secagent · my-shop  (nextjs, git)

  Last scan   2 days ago · Needs attention: 1 high-priority issue(s) · high 1, medium 2
  Websites    https://shop.example.com (prod)
  Servers     web-1 (prod) · no collector output yet
  Accepted    1 risk(s); the soonest ends in 5 day(s)

  Next: web-1 has no collector output yet, so I cannot check its SSH, nginx or packages. Add it next.
```

**Next** is chosen by fixed rules, in this order: run the first scan; add a server's missing or stale collector output; fix open critical or high issues; look at an accepted risk that ends within 7 days; scan again when a listed site or server has no result yet or the last scan is over 7 days old; export the review checklist. The suggested item comes first in the menu.

| Menu item | What it does |
|---|---|
| See what to fix first | The open issues, most urgent first; pick one for what was found, why it matters, the fix and the evidence |
| Scan again | Same settings, fresh scan, compared with the last one. In a new session it asks for permission first |
| Open the report | The PDF or HTML report |
| Review what the scan can't see | Writes the review checklist for the areas that fit the project to `.secagent/reports/checklist.md` and says how to work through it |
| Add a server's collector output | Writes the read-only collector, says how to run it, stores its output (as `secagent snapshot add`) |
| Accepted risks | Lists them with their end dates; accept the risk of another finding |
| Check a scanner's CVE claim | The same verdict as `secagent verify` |
| Review lessons an AI assistant proposed | Approve or reject each |
| Connect an AI assistant | The `secagent mcp setup` command and what to ask |
| Settings and setup | Change what is checked, start over, or check this machine (`secagent doctor`) |
| How secagent works | The step-by-step guides |

An item shows only when it applies: without servers there is no collector or CVE item.

## Scanning without questions

For scripts, CI and repeat runs.

```bash
# create .secagent/project.yaml without questions (repeat --target / --host as needed)
secagent init --name shop --scan-label office \
  --target app=https://shop.example.com,web,prod \
  --target api=https://api.example.com,api,prod \
  --host web-1=203.0.113.10,prod

# run the checks and write the reports
secagent scan                                  # everything
secagent scan --only code                      # only one area: code, web or host
secagent scan --only web,host                  # or several (comma-separated or repeated)
secagent scan --only code --fail-on high       # exit 1 if an open finding is high or critical
```

- `--target id=url,web|api,env`: the id is lowercase letters, digits and dashes.
- `--host name=address,env`: a server by name and address.
- `--only` runs just those areas; the other areas keep their results from the last scan and the report marks them "from an earlier scan".
- `--fail-on` takes `critical`, `high`, `medium`, `low` or `info`.
- `secagent scan` counts as your confirmation of what `project.yaml` lists. If you did not write that file, read it first.

Other options for `scan`: `--dir <path>` to scan a folder other than the current one; `--no-ai` is accepted and ignored (a scan never uses AI).

## Scanning a server

secagent never logs in to a server. A person with access runs a read-only script and hands over its output.

```bash
secagent collector --host web-1 --out collect.sh     # writes the script; prints how to run it
scp collect.sh web-1:/tmp/ && ssh web-1 'sudo sh /tmp/collect.sh' > web-1.json
secagent snapshot add --host web-1 web-1.json        # validates and stores it
secagent scan --only host
```

- The script reads package, SSH, nginx and listening-socket state, redacts secrets, and prints one JSON document. It is plain `sh`; read it before you run it.
- Package advisories (pending security fixes) are checked for **Ubuntu and Debian**. On other systems (Amazon Linux, RHEL, Alpine) the package checks report "could not verify". The SSH, nginx and listening-port sections do not need `apt`, so those checks are designed to still run; this has not been tested on non-Debian systems yet.
- A snapshot older than 7 days is reported as stale. Collect again before relying on the result.
- `secagent learn` refreshes the public advisory data (CISA KEV, OSV, Ubuntu) for the stored snapshots.
- A scanner told you "CVE-2024-6387 affects this server"? `secagent verify --host web-1 --cve CVE-2024-6387` decides it from the server's installed package version and the distro's own advisory, so a backported fix is not reported as a vulnerability.

## Reading the report

Open `.secagent/reports/latest.pdf` (or `.md`, or the self-contained `.html`).

| Part | Meaning |
|---|---|
| **Verdict** | One line: needs attention (high or critical open), some issues, no open issues but accepted risks or unverified checks, or none. |
| **Fix first** | The most important open findings, with where they are. |
| **Findings** | For each: what was found, why it matters, how to fix it for your stack, a link to learn more, and the evidence id. |
| **Could not verify** | Checks that could not run (no server snapshot, plain-HTTP site with no TLS, a timeout). These are unknown, never counted as passed. |
| **Accepted risks** | Findings a person accepted until a date. |
| **Marked not a problem** | False positives an AI assistant marked, each backed by approved knowledge. |

Severities: `critical`, `high`, `medium`, `low`, `info`. Finding statuses: `open`, `fixed`, `unverifiable`, `accepted_risk`, `false_positive`, `not_applicable`.

A finding id looks like `hdr-csp@app` (check `hdr-csp` on target `app`), `code-secrets-history@code` for the code, `host-ssh-root-login@web-1` for a server. Use it with `accept`.

`secagent report` re-renders the latest scan's report without scanning again. Evidence records (what was observed, with the network the scan ran from) are in `.secagent/evidence/`, and the machine-readable result is `.secagent/findings/latest.json`.

## Fixing and checking again

1. Fix the first finding (the report gives the change for your stack, and warns about side effects such as new headers exceeding a proxy buffer).
2. Run `secagent scan` (or `secagent` and *Scan again*).
3. The scan prints `Diff vs previous scan: new, fixed, regressed`. A finding that returns after being fixed is reported as regressed.

## Accepting a risk

Some findings cannot be fixed today. A person can accept one for a limited time:

```bash
secagent accept hdr-csp@app --owner "Priya" --reason "CSP rolls out with the new proxy" --until 2026-12-15
```

It is saved to `.secagent/knowledge/exceptions.yaml` (commit it). The next scan lists it under accepted risks, the verdict says so instead of "no issues", and it counts as open again the day after the date. Only open findings can be accepted, for at most a year ahead. An AI assistant cannot do this.

## The review checklist: what the scan cannot check

The scan decides what a tool can prove from outside or from files. Many ways in sit in the code and the cloud setup, and need someone to read them. `secagent checklist` gives the rules for that, in five areas:

| Area | `--area` | Covers |
|---|---|---|
| Public surface and APIs | `surface` | login on every route, ownership checks on ids (IDOR), admin roles checked on the server, fields in responses, rate limits, API docs and debug endpoints, old versions and staging, CSRF, abuse of costly flows |
| Authentication and sessions | `auth` | password hashing, login throttling, JWT, session lifetime, password reset, account enumeration, MFA for admins, default accounts, OAuth |
| Input handling | `input` | SQL and NoSQL injection, command injection, XSS, validation, mass assignment, SSRF, path traversal, uploads, open redirects, unsafe deserialization, webhooks |
| Secrets, configuration and logging | `secrets` | secrets in config files and Terraform state, secrets in frontend bundles, secret management, debug mode, error pages, logging, TLS verification, a security contact |
| Cloud, containers and supply chain | `infra` | firewall and security-group exposure, public buckets, IAM, IMDSv2, account MFA and audit logs, containers, dependencies, CI/CD, branch protection, patching, backups |

Every item says when it applies, why it matters, where to look (with names for common frameworks: Express, NestJS, Next.js, Django, FastAPI, Spring), when it fails or passes, what evidence to keep, how to fix it, and an OWASP or vendor source. Items the scan covers in part show its latest result, so nobody re-checks those by hand.

```bash
secagent checklist                         # all areas, printed
secagent checklist --area auth,input       # some areas
secagent checklist --out review.md         # to a file, to work through or hand to an AI
```

Ways to use it:

- **Claude Code with the MCP server:** `/security-review` scans, then works through the checklist with the code (the `get_checklist` tool).
- **Any other AI assistant:** run `secagent checklist --out review.md`, give it the file with access to the code, and ask it to answer every item that applies with pass, fail or unknown and file:line evidence.
- **By hand:** go through `review.md`, for example as part of a release or a pull request review.

The answers are an assessment by whoever worked through the list. secagent does not store them, and they never change scan findings or the verdict. Re-run the scan after fixing anything it checks.

## Safety: what it will and will not touch

- **Scope.** Only the websites and servers in `.secagent/project.yaml` are probed. Any other address is refused, including one a page redirects to, because redirects are not followed.
- **Consent.** Your yes is stored in `~/.config/secagent/consent.json`, outside the project, so a cloned repository cannot confirm its own `project.yaml`. It is tied to the listed addresses: after you change one, an AI assistant cannot probe until you run `secagent` or `secagent scan` here again. `secagent doctor` shows whether the scope is confirmed.
- **Private and cloud-metadata addresses.** Private addresses need `allow_private: true` on that entry. Link-local addresses such as `169.254.169.254` (cloud metadata) are never probed.
- **Read-only.** `GET` and `HEAD` requests, TLS handshakes and TCP connection tests. No logins, no form posts, no guessing.
- **Your data.** Code and files stay on your machine. The npm dependency check and the server package check send package names and versions to public advisory databases (OSV, Ubuntu Security, CISA).
- **Scan only what is yours.** Scan systems you own or have written permission to test.

## The project folder

secagent keeps its state in `<project>/.secagent/`:

| Path | Commit it? | What |
|---|---|---|
| `project.yaml` | yes | what to check; the only addresses secagent will probe |
| `knowledge/exceptions.yaml`, `notes.md`, `lessons/` | yes | accepted risks, project notes, the project's own lessons |
| `reports/` | no | `latest.md`, `latest.pdf`, `latest.html` |
| `findings/`, `evidence/` | no | scan results and recorded observations |
| `hosts/` | no | collector scripts and server snapshots |

`secagent init` writes a `.gitignore` in `.secagent/` that covers the "no" rows.

### project.yaml

```yaml
version: 1
name: shop
stack:                       # picks the fix advice; detected automatically
  frontend: nextjs
  backend: nestjs
  proxy: nginx
  hosting: vercel
network:
  ip_family: 4               # 4 or 6
  scan_label: office         # where you scan from; written on every piece of evidence
code:
  enabled: true
  exclude: ["docs/examples/**"]   # gitignore-style globs the code checks skip
  history: true              # also scan git history for removed secrets
  max_files: 20000
  max_file_bytes: 1000000
targets:
  - id: app                  # lowercase letters, digits, dashes
    url: https://shop.example.com
    type: web                # web or api
    env: prod
    allow_private: false     # true to probe a private address
hosts:
  - name: web-1
    address: 203.0.113.10
    env: prod
    role: web
    serves: [app]            # target ids this server serves
    reachable_from: []
    allow_private: false
    distro_mirrors: []       # apt mirror host names you vouch for as copies of the official archive
```

## Every command

Every command has its own page: `secagent help <command>` or `secagent <command> --help`. Step-by-step guides: `secagent help first-scan`, `servers`, `ai`, `ci`, `safety`. A mistyped command gets a "Did you mean" suggestion.

| Command | What it does |
|---|---|
| `secagent` / `secagent start [--dir]` | The guided scan (on a terminal) |
| `secagent init [--dir] [--name] [--scan-label] [--target id=url,web\|api,env] [--host name=address,env]` | Create `.secagent/` and `project.yaml` without questions |
| `secagent scan [--dir] [--only code\|web\|host] [--fail-on <severity>]` | Run the checks and write the reports |
| `secagent report [--dir]` | Re-render the report of the latest scan |
| `secagent doctor [--dir] [--offline]` | Check the machine and project, with a fix for each problem |
| `secagent collector --host <name> [--out <file>] [--dir]` | Print or write the read-only server script |
| `secagent snapshot add --host <name> <file> [--dir]` | Validate and store the script's output |
| `secagent verify --host <name> --cve <id> [--package <name>] [--json] [--dir]` | Is a scanner's CVE claim true for this server? |
| `secagent learn [--dir]` | Refresh CISA KEV and package advisories for stored snapshots |
| `secagent accept <finding-id> --owner <n> --reason <t> --until <YYYY-MM-DD> [--dir]` | Accept an open finding's risk until a date |
| `secagent checklist [--area <id>] [--out <file>] [--dir]` | The review checklist for what the scan cannot check, with the latest scan's results for items it covers in part |
| `secagent eval <expected.yaml> [--dir]` | Compare the latest scan with expected statuses (`findings: { <id>: <status> }`); exit 1 on a difference |
| `secagent mcp [--dir]` | Serve the project to an AI client over MCP |
| `secagent mcp setup` | Print the command that connects Claude Code or another client |
| `secagent kb review [--approve <id> --by <name>] [--reject <id>] [--dir]` | List, approve or reject lessons an AI assistant proposed |
| `secagent kb index` | Regenerate `knowledge/INDEX.md` (maintainers) |
| `secagent version` / `--version` | Print the version |
| `secagent help [<command> \| <guide>]` | The overview, one command's page, or a guide |

Environment variables: `SECAGENT_CACHE_DIR` (advisory cache, default `~/.cache/secagent/advisories`), `SECAGENT_CONFIG_DIR` (where the consent file lives, default `~/.config/secagent`), `NO_COLOR` (plain output).

Exit codes: `0` success; `1` a failed `--fail-on` gate, a failed `eval`, or an error with a message (bad option, no project, address not in scope); `2` an unexpected crash.

## Recipes

**First look at a project.** `cd project && secagent`, tick code and websites, answer the questions, open the PDF.

**A site on EC2, behind a load balancer, or on Vercel/Netlify.** The hosting does not matter for the website checks: list the public URL as a website or API. If a load balancer or WAF fronts a server, also list the server and set `serves: [<site id>]` on it in `project.yaml`; the load-balancer bypass check then tests whether the server also answers on its own address, around the load balancer. Without `serves`, that check has nothing to test and passes.

**Staging and production.** List both as separate targets with `env: staging` and `env: prod`. Each gets its own findings.

**An API.** List it with type `api`. The checks that only make sense for pages (CSP, framing, Permissions-Policy) are skipped for APIs.

**A dev server on your machine.** Use `http://127.0.0.1:3000`; answer yes to the private-address question (or set `allow_private: true`).

**CI gate on every pull request.** Commit `.secagent/project.yaml`, then:

```yaml
# .github/workflows/secagent.yml (example)
name: secagent
on: [pull_request]
permissions: { contents: read }
jobs:
  code:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }          # full history for the secrets-in-history check
      - uses: actions/setup-node@v4
        with: { node-version: 22 }
      - run: |
          git clone --depth 1 https://github.com/manjeet-55/security-agent.git "$RUNNER_TEMP/secagent"
          (cd "$RUNNER_TEMP/secagent" && npm ci && npm run build)
      - run: node "$RUNNER_TEMP/secagent/dist/cli.js" scan --only code --fail-on high
```

**A full review with an AI assistant.** Run `secagent` (scan), then in Claude Code run `/security-review`, or with another assistant give it `secagent checklist --out review.md` and the code. Ask for the fails first, by severity, with file:line.

**Prove a fix to a reviewer.** Run `secagent scan`, attach `.secagent/reports/latest.pdf`; the diff section lists what was fixed.

**Let an AI assistant help.** `secagent mcp setup` prints the connection command; the assistant can scan, explain and re-check but cannot change what is probed or accept a risk. See [mcp.md](mcp.md).

## Troubleshooting

| Message or symptom | Fix |
|---|---|
| `No project config at ... Run "secagent init" first` | Run `secagent` in the project folder. |
| `"x" is not in project.yaml` | The address is out of scope. Add it with `secagent` (Change the settings) if it belongs to this project. |
| `resolves to private address(es)` | Set `allow_private: true` on that entry, or answer yes to the private-address question. |
| `Unknown command` after pulling new code | `npm run build`. |
| Arrow keys move but the first option stays ticked | Arrow keys only move the pointer; press **space** to tick or untick. |
| A check shows `?` (could not verify) | Read the reason in the report. Common causes: no server snapshot, a non-HTTPS site for the TLS checks, a timeout from a network that is not allowlisted. |
| `UNSUPPORTED_DISTRO` | Package advisories cover Ubuntu and Debian only; the other server checks still run. |
| Advisory database unreachable | `secagent doctor` says so; dependency and package checks become "could not verify" until it is reachable. |

## Limits today

- Dependency scanning covers npm (`package-lock.json`) only.
- Package advisories cover Ubuntu and Debian only.
- It checks the addresses you list; it does not discover other sites, subdomains or endpoints on its own.
- It does not test logged-in behaviour: authorisation, business logic and injection flaws are not probed. The review checklist covers them for a person or an AI assistant reading the code.
- Server checks depend on a snapshot a person collects; secagent does not log in.
