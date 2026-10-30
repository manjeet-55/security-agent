# secagent: overview

## The problem

Security checks are usually a pile of separate tools, flags and config files, and the output is written for specialists. A developer who just deployed a site wants to know "is this safe, and what do I fix first?" without learning five tools. Scanners also cry wolf: a server can be patched against a CVE while a banner-based scanner still reports it.

## What secagent does

Run `secagent` in a project folder. It:

1. looks at the project (stack, git) and **asks for what it needs**: deployed URLs, environment, servers, where you are scanning from;
2. shows what it will do and **asks for permission** before touching any website or server;
3. scans **code** (secrets, `.env` and key files, git history, npm dependencies), **websites and APIs** (security headers, cookies, CORS, redirects, TLS, exposed files, dangling DNS) and **servers** (SSH, nginx, packages against distro advisories, load-balancer bypass) with live progress;
4. writes a **report anyone can read**, as Markdown, PDF and HTML: a verdict, what to fix first, and for each finding what was found, why it matters, how to fix it for your stack, and the evidence.

An AI assistant (Claude Code, Cursor, any MCP client) can drive the same scan through `secagent mcp`. It explains and prioritises; secagent still decides every status.

What no scanner can decide (a route without an auth guard, a query without an ownership check, a public bucket) is covered by a **review checklist** (`secagent checklist`): sourced rules saying where to look in the code, how to decide and how to fix, for a person or an AI assistant that can read the code. Their answers are labelled as their assessment and never change the scan's findings.

## What makes it trustworthy

- **Evidence or nothing.** Every finding cites a recorded observation. A check that could not run is `unverifiable` and listed apart from "passed"; it is never a pass.
- **Permission and scope.** Only the websites and servers in `project.yaml` are probed, only after an explicit yes, and private addresses need a separate yes.
- **Secrets stay put.** Reports and tool results carry file, line, pattern and a short fingerprint, never the value. A test plants every secret type and checks that none appears in any output or file.
- **Distro-aware CVE checks.** `verify_claim` decides a scanner's CVE claim from the host's installed package version and the distro's own advisory, so a backported fix is not reported as a vulnerability.
- **Honest about gaps.** A partial scan labels the areas it did not re-check; an accepted risk (`secagent accept`) is listed in its own section, expires on a date, and keeps the verdict from reading "all clear".
- **Deterministic.** No AI model in the scan: the same inputs give the same result, with no API key. Your code and files never leave your machine; server checks send only package names and versions to public advisory databases (OSV, Ubuntu Security, CISA).

## How it is built

TypeScript on Node 20+, three runtime dependencies besides the MCP SDK (`yaml`, `zod`, `pdfkit`), no prompt or UI library.

| Layer | Where | Does |
|---|---|---|
| Guided scan and home screen | `src/wizard/`, `src/home/`, `src/help/`, `src/ui/` | first-run intro, questions, consent, live progress; a home screen with the project's status, a suggested next step and every action; built-in help and guides; a small prompt layer on `node:readline` |
| Engine | `src/scan/`, `src/checks/` | 14 check types, 33 seed checks as YAML (stack-specific fixes, plain-language "why"), run through a scope guard |
| Code scanner | `src/code/` | secret patterns with entropy filter, `.env`/key hygiene, streamed git-history scan with limits |
| Evidence and findings | `src/evidence/`, `src/findings/` | recorded observations, stable finding ids, diff between scans, accepted risks |
| Report | `src/report/` | one block model, two renderers (Markdown, PDF) |
| Knowledge base | `knowledge/`, `src/kb/` | seven sourced lessons from real remediations, per-project lessons and exceptions |
| Review checklist | `knowledge/checklists/`, `src/kb/checklist.ts` | 49 sourced rules in five areas for what a scanner cannot decide (authorization, input handling, secrets in config, cloud, CI), for a person or an AI with the code; linked to the checks that cover them in part |
| MCP server | `src/mcp/` | 16 tools and a `security_review` prompt over stdio; cannot change what is probed, accept a risk or add a server snapshot; scanned text is marked untrusted |
| Agent layer | `agent/` | the playbook AI clients follow, and a Claude Code plugin with a `/security-review` command |
| Host collector | `assets/collector.sh` | read-only script run on a server, output validated and stored |

About 1,000 automated tests, including real HTTPS/TLS servers, real git repositories, a real MCP client over stdio, and the built binary run in a terminal.

## Try it

`docs/demo.md` is a five-minute script: a sample project that leaks in four ways plus a deliberately weak local website. `README.md` has install and a summary; `docs/usage.md` is the full guide to the workflow and every option; `docs/mcp.md` covers AI-client setup.

## Limits and next steps

- Learning is reviewed, not automatic: an AI assistant can propose a lesson that quotes an allowlisted page word for word, and it stays pending until a person approves it. New check types are still written by people.
- Server checks need the collector's output from a person with access to the server; secagent never logs in.
- Dependency scanning covers npm (`package-lock.json`) only; other ecosystems are not checked yet.
- Package advisories cover Ubuntu and Debian only; Amazon Linux and other systems report them as "could not verify".
- It checks only the addresses it is given; it does not discover endpoints, subdomains or public APIs on its own.

Released under the MIT license ([LICENSE](../LICENSE)).
