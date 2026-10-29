# secagent: Guided Agent Design

Date: 2026-10-29. Status: approved by the owner in conversation. Amends the main spec (`2026-10-28-secagent-design.md`), mainly §9 (agent layer), §10 (reports), §11 (CLI) and §16 (delivery plan).

## 1. Why

The team wants secagent to feel like other AI agents. You start it with one command inside a project folder. It asks for whatever it needs (deployed URLs, environment, servers) instead of expecting flags or a hand-edited `project.yaml`. It finishes with a report a non-expert can read, as Markdown and PDF. The first use is a live demo, so it must work every run with no API key and no external service.

## 2. Decisions

| Decision | Choice | Why |
|---|---|---|
| Interface | Terminal wizard: bare `secagent` (or `secagent start`) | Works anywhere Node runs, including over SSH. Matches how CLI agents feel. Smallest build. |
| LLM | None in the wizard for now | The same result on every run, no key, no data leaves the machine. Plain-language text comes from the knowledge base. An opt-in LLM summary can come later. |
| Prompts | Own small module on `node:readline` | No dependency for a few prompt kinds. Testable through an interface. |
| Report | Markdown and PDF from one block model | Both renderers read the same blocks, so they cannot disagree. |
| PDF | `pdfkit` 0.20.2, exact pin, installed with `--before` a date at least two weeks back | Pure JavaScript, built-in Helvetica, no browser or font files. The only new runtime dependency. |
| Old Plan 3 | KB read, `findings_write`, MCP server and playbook move to Plan 4 | They do not block the demo. Nothing is deleted. |

Rejected: `@clack/prompts` (a second dependency for little gain), a full-screen TUI such as Ink (heavy, risky on stage), and a local web UI (more to build; can sit on the same engine later).

## 3. What the user sees

`cd my-project && secagent`

1. **Look around.** A header with the project name and detected stack (`detectStack`), and whether the folder is a git repository. If `.secagent/project.yaml` exists, it shows a short summary and offers *Scan again with these settings*, *Change settings* or *Start over*. *Change settings* re-asks every question with the current values as defaults.
2. **What to check.** A multi-select over *This project's code* (on by default), *Deployed websites or APIs* and *Servers*.
3. **Websites or APIs**, asked in a loop:
   - URL: `http` or `https`, validated.
   - Kind: web or API.
   - Environment: prod, staging, dev, or other (free text).
   - "Add another?"
   An id is derived from the hostname (`portal-example-com`) and made unique. If the URL's host is an IP literal in a private range, or resolves to one (one DNS lookup), the wizard says so and asks before setting `allow_private`. Without a yes, the URL is not added.
4. **Where are you scanning from?** Office, home, VPN, cloud/CI, or other. This is the scan label stamped on every piece of evidence. The question is skipped when only code is checked; the label then stays `local`.
5. **Servers**, asked in a loop:
   - Name, address and environment.
   - The wizard prints the one-line command to run on the server, and offers to write the read-only collector to `.secagent/hosts/<name>/collector.sh`. This is the only file written before the save step, and only if you say yes.
   - It then asks for the path of the output file. *Enter* skips it. The file is validated at once (the same parsing as `snapshot add`); on an error the wizard shows the message and asks again or lets you skip. It is stored only at the save step.
   - A server without a snapshot is reported as *not checked*, never as fine.
6. **Review and consent.** One screen lists what will happen:
   - read-only requests to these URLs (GET, TLS handshakes) and to these server addresses (TCP connects to the listed ports);
   - a scan of this folder and its git history;
   - nothing is changed, and nothing is sent anywhere else.
   When any URL or server is listed, it asks: "I own these systems or have written permission to test them (y/N)". Without a yes, nothing is saved and nothing is probed; the wizard offers to go back or to scan only the code. A code-only scan needs no consent.
7. **Save.** `project.yaml` is written only now, through `initProject`/`saveProject`, and the snapshot files are stored. Ctrl+C before this point leaves the folder as it was, apart from a collector script you asked for.
8. **Scan with live progress.** One line per check as it finishes (`✓` pass, `✗` fail, `?` could not verify, `!` error), grouped by area, with a running count `12/33`.
9. **Result.** A one-line verdict, counts by severity, the top three fixes, and the absolute paths of the Markdown and PDF report. Then *Open the report* (spawns `xdg-open`, `open` or `start` with an argument array; on failure it prints the path), *Scan again* or *Exit*.

Verdict rules:
- any critical or high finding open → *Needs attention* (red);
- otherwise any open → *Some issues to fix* (yellow);
- otherwise any check could not be verified → *No issues found, but N checks could not be verified* (yellow);
- otherwise → *No issues found* (green).

Colour is used only on a TTY and only when `NO_COLOR` is unset.

Bare `secagent` in a non-interactive shell (no TTY on stdin or stdout) prints the usage, as today. `secagent start` without a TTY exits 1 with: "secagent start needs an interactive terminal. In scripts, use secagent init and secagent scan --no-ai." The existing subcommands keep working unchanged.

## 4. Components

| Unit | Does | Depends on |
|---|---|---|
| `src/ui/prompt.ts` | `Prompter` interface: `text`, `confirm`, `select`, `multiselect`, `note`. The TTY implementation uses raw-mode keys (arrows, space, enter, Ctrl+C) and redraws only its own lines. | `node:readline` |
| `src/ui/style.ts` | ANSI colours and symbols, off when not a TTY or `NO_COLOR` is set | nothing |
| `src/wizard/questions.ts` | Asks the questions, returns a `WizardPlan` (project config, consent time, snapshot files). Writes nothing. | `Prompter`, `detectStack`, `isPrivateAddress`, `resolveAddresses` |
| `src/wizard/run.ts` | Saves the plan, runs the scan with progress, writes the report, shows the result screen | questions, `scanNoAi`, report |
| `src/scan/no-ai.ts` | Gains `onPlan(total)` and `onResult(result)` callbacks, and records `consent_at` | as today |
| `ScanRecord` | Gains optional `consent_at` (ISO time of the consent yes), so a re-rendered report keeps the consent line | schema |
| `src/report/model.ts` | `buildReport(input) → Block[]` (the block model from Plan 3 Task 7) | `ScanRecord`, check instances |
| `src/report/markdown.ts` | `renderMarkdown(blocks) → string` | model |
| `src/report/pdf.ts` | `renderPdf(blocks, opts) → Promise<Buffer>` | model, `pdfkit` |
| `src/report/write.ts` | Writes `.secagent/reports/<YYYYMMDD-HHMMSS>/report.{md,pdf}` and copies them to `.secagent/reports/latest.{md,pdf}` | renderers |

`.secagent/reports/` is already gitignored, and the code scanner never reads `.secagent/`.

`scan --no-ai` also writes the report and prints its paths. A new `secagent report [--dir]` re-renders it from `findings/latest.json`.

## 5. The report

It is written for a reader who is not a security specialist. Every number and status comes from the scan record. No text is invented at report time.

1. **Title and meta.** "Security report: <project>", date, network label, and "deterministic scan, no AI".
2. **Verdict.** The same rules as the result screen, as a coloured line in the PDF.
3. **At a glance.** A table with the columns Area, Checks, Issues, Could not check, and one row each for *Code*, *Websites and APIs* and *Servers*. Areas that were not selected are omitted.
4. **Fix first.** Up to five open findings, ordered by severity then id, each in one line: title, where, and the first sentence of the fix.
5. **Findings.** For each open finding, a heading with the severity and title, then:
   - *Where*: the URL, "this project's code", or the server name and address;
   - *What we found*: the result's `observed`;
   - *Why it matters*: the check's new `why` field;
   - *How to fix*: `fix.how`, which is stack-specific;
   - *Learn more*: `source_url`;
   - *Evidence*: the evidence id(s).
6. **Could not verify.** A table with Check, Where, Reason (`observed`), and the sentence "These are not passes: fix the cause and scan again."
7. **Fixed since the last scan.** Present when `diff.fixed` is not empty.
8. **Passed.** A compact list grouped by area.
9. **About this scan.**
   - The targets, servers and code in scope.
   - The consent line ("Scope confirmed by the person running the scan on <time>") when the record has `consent_at`; otherwise "Run from the command line".
   - The method: read-only and deterministic.
   - "A check that could not run is never counted as passed".
   - "Secret values are never shown, only file, line and a fingerprint".

**`why` field.** `CheckInstanceSchema` gains an optional `why: string` (one or two plain sentences). All 29 seed checks get one. A test asserts that every seed check has it. Learned checks may omit it; the report then falls back to the title.

**PDF.**
- A4 with a header line and "page n of m" footer.
- Helvetica and Helvetica-Bold.
- Severity shown as a coloured label.
- Tables drawn with wrapped cells, and a page break before a row that would not fit.
- `info.CreationDate` set to the scan time.

pdfkit writes text as hex glyph strings, so the PDF is tested as a smoke test (`%PDF-` header, page count, size). Content and the no-leak rule are tested on the blocks and the Markdown, which come from the same blocks.

## 6. Errors and safety

- Fail-closed rules are unchanged. The wizard cannot turn an unverifiable result into a pass, and the report keeps *Could not verify* apart from *Passed*.
- No probe runs without the consent yes. Every URL and server still goes through `Scope`, as today.
- The no-leak test is extended to the report files. Report text is built only from results, findings and check instances, never from file contents.
- A scan error (for example `project.yaml` invalid after a hand edit) shows its message and offers *Change settings* or *Exit*. The wizard never shows a stack trace for a known error type.
- Ctrl+C at any prompt exits with code 130, after restoring the terminal mode.

## 7. Demo kit (cuttable)

`npm run demo:setup -- <dir>` creates a sample project:
- a small app with fake secrets built by string concatenation, as in the tests;
- a tracked `.env`;
- a key that a later commit removes, so it stays in history;
- an untracked, unignored `server.key`.

The repository itself never holds real-looking tokens.

`npm run demo:server` starts a local HTTP server on `127.0.0.1:8080` that sends no security headers and serves `/.env`. On stage: start the server, then `cd <dir> && secagent`. Pick code and website, enter `http://127.0.0.1:8080`, allow the internal address, confirm consent, and open the PDF.

## 8. Testing

- **Prompt layer.** Key handling on a fake TTY stream (arrows, space, enter, Ctrl+C), and that the terminal mode is restored.
- **Wizard.** Whole flows with a scripted prompter (`test/helpers/prompter.ts`: answers in order, fails loudly on an unexpected question):
  - code only;
  - website against the local HTTPS test servers;
  - a private address declined, then accepted;
  - consent declined;
  - re-run with existing settings;
  - a server skipped.
- **Report.** Markdown for a fixed record (section order, verdict rules, the *Could not verify* split); a PDF smoke test; and every seed check has a `why`.
- **No-leak.** Covers the Markdown report and the blocks.
- **CLI.** Bare `secagent` without a TTY prints the usage. `start` without a TTY exits 1. `scan --no-ai` prints the report paths.

## 9. Delivery: new Plan 3 (guided agent)

1. Report model, Markdown renderer, `report` command, report after `scan --no-ai`.
2. `why` on every seed check.
3. PDF renderer (adds `pdfkit`).
4. Prompt layer and scripted prompter.
5. Wizard questions.
6. Wizard run: progress callbacks, result screen, `start` and bare `secagent`.
7. Demo kit (cuttable).

Every task ends with the suite and `tsc` green, and is runnable on its own. Plan 4 then takes the old Plan 3 tasks: KB read, `findings_write` trust rule, MCP server, playbook, distro mirrors, and the cut items (HTML report, `fetch_source`, Claude plugin, eval, CI), plus an opt-in LLM summary.
