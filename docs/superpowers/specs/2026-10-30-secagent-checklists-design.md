# secagent: Review Checklists Design

Date: 2026-10-30. Status: approved by the owner in conversation ("provide a checklist; add a tool only where one is possible").

## 1. Why

The scan checks what a deterministic tool can prove from outside or from files: headers, TLS, exposed files, secrets, dependencies, server settings. Most ways attackers break in are not like that: a route without an auth guard, a lookup by id without an ownership check, SQL built from strings, a public bucket. Finding those needs someone to read the code and the cloud configuration.

The people running secagent have the code and an AI assistant. secagent gives them the rules: what to look for, where, how to decide, what evidence to keep, and how to fix it. A tool is added only when a check can be made deterministic and reliable.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Form | YAML items in `knowledge/checklists/<area>.yaml`, validated with zod | Same shape and review rules as the check catalogue; reviewable in a pull request |
| Areas | `surface` (public surface and APIs), `auth`, `input`, `secrets` (secrets, config, logging), `infra` (cloud, containers, supply chain) | The usual ways in, grouped by where a reviewer looks |
| Link to the scan | `automated_by: [check ids]`; the rendered checklist shows the latest scan's outcome for those checks | One list covers both; nobody re-checks by hand what the scan already decides |
| Delivery | `secagent checklist` (Markdown to stdout or `--out`), MCP `get_checklist`, playbook step, `/security-review` step | Works with any AI (paste it), with Claude Code through MCP, or by hand |
| Answers | Not recorded by secagent in this version | Answers are an assessment, not evidence; keeping them out of the scan keeps "every status comes from secagent" true. Recording them in a labelled report section is a possible next step |
| Sources | Every item cites an allowlisted page (`knowledge/sources.yaml`) | Same rule as checks and lessons |

## 3. Item

```yaml
id: surface-auth-by-default        # unique across all checklists, lowercase-dashes
title: Every route that returns or changes data requires login, or is deliberately public
severity: high                     # what failing it usually means
applies_if: The project serves an API or server-rendered pages   # optional; otherwise always applies
why: One or two plain sentences: what an attacker gains.
look_for:                          # where and what to search, with names per stack
  - ...
fail_if: ...
pass_if: ...
evidence: What to cite for the answer (file:line, a config value)
fix: The usual fix
source_url: https://owasp.org/...  # allowlisted, https
automated_by: [exposed-paths]      # optional: scan checks that cover part of the item
```

A checklist file is `{ area, title, items }`; `area` equals the file name. Loading fails on an unknown field, a duplicate id, an `automated_by` id that is not in the check catalogue, or a source not on the allowlist.

## 4. Output

`renderChecklist` writes Markdown: how to work through it (applies if, look for, decide with fail if / pass if, cite evidence, answers are assessments), the latest scan time, a contents table (id, title, severity, automated), then each area with its items. For an item with `automated_by`, a line gives each check's latest outcome per target ("passed on app, failed on api", "not in the latest scan", "no scan yet").

`secagent checklist [--dir] [--area <id>]... [--out <file>]` and `get_checklist { areas? }` both return it. `knowledge/INDEX.md` lists the items.

## 5. Tools added alongside

`exposed-paths` also probes `/.env.production`, `/.env.local`, `/actuator/env` (Spring Boot) and `/server-status` (Apache), each with a content signature, because those can be decided deterministically.

## 6. Testing

Schema rejects bad items; the shipped checklists load (unique ids, known checks, allowlisted sources); rendering shows outcomes from a scan record and "no scan yet" without one; the CLI filters by area, rejects an unknown one, writes `--out`; the MCP tool is listed and returns the Markdown; `INDEX.md` stays current.
