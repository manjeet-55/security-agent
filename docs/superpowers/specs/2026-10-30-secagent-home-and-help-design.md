# secagent: home screen and help

- **Date:** 2026-10-30
- **Status:** design approved, implementation not started
- **Builds on:** [2026-10-29-secagent-guided-agent-design.md](2026-10-29-secagent-guided-agent-design.md)

## 1. Problem

secagent's pieces all serve one goal: a developer runs it on their project and learns what an attacker would hit first, what proves it, and what to fix. What lets a new user down is the front door:

- The guided scan (`secagent`) exposes one path, scanning. The checklist, connecting an AI assistant, adding a server's collector output, checking a CVE claim and `doctor` are reachable only by someone who already knows the command.
- `secagent help` prints 17 commands in one flat list, in no particular order. There is no help for a single command (`secagent scan --help` fails with `Unknown option '--help'`).
- Nothing says what to do next based on where the project stands (never scanned, a server without collector output, an accepted risk about to expire).

The owner wants using secagent to feel like working with an AI agent, without changing how it works.

## 2. The rule: a UI layer only

This work adds a presentation layer. It does not change behaviour below it.

- **Unchanged:** the engine, checks, scope guard, consent, evidence, findings, report, every CLI command's options and output, the MCP server, the playbook. Every home-screen action calls the same function its CLI command calls, with the same arguments.
- **No AI model, no randomness.** The "agent" feel comes from fixed text and rules (section 5). The same project state always gives the same screen and the same suggestion.
- **No network before consent.** The home screen reads local files only. Network checks run only through the existing scan path, after the existing consent question.
- **Consent works as today.** A rescan in the same session reuses that session's consent; a new session asks again before probing; accepting a risk triggers a rescan.
- **Secret values are never shown.** Home-screen text uses the same finding fields as the report.
- **No new dependencies.**
- **Tests:** existing tests pass unchanged, except the wizard tests that cover the two menus this work moves (the end-of-run "What next?" menu and the "already set up" question).

## 3. First run

When `.secagent/project.yaml` does not exist, `secagent` (or `secagent start`) on a terminal:

1. **Intro**, one screen, in the agent's voice:
   ```
   secagent · security check for this project

   I look at your project the way an attacker's first pass would, then tell you what to fix first.
     • Code: secrets, .env and key files, git history, npm packages
     • Websites and APIs you give me: headers, TLS, cookies, exposed files
     • Servers you give me: SSH, nginx, packages (you run a read-only script on them)

   I never log in, guess passwords or change anything. I only send read-only requests, only to
   addresses you list, and only after you say I may. Secret values are never printed.

   ? Shall we start?
     ❯ Set up and scan this project
       How secagent works first
       Quit
   ```
   "How secagent works first" shows the guides (section 6.3), then returns to this question.
2. **Setup questions and consent:** `askPlan`, unchanged.
3. **Scan** with live progress and the verdict: `scanWithProgress` and `showResult`, unchanged.
4. **Home screen** (section 4) instead of today's "What next?" menu.

A non-terminal run without a command prints the help overview, as today.

## 4. Home screen

Every later run of `secagent` goes straight to the home screen, which also follows the first scan. It loops (status, then the suggested next step, then the menu, then the chosen action, then back to status) until the person chooses Exit or presses Ctrl+C.

### 4.1 Status

`projectStatus(dir, now)` reads, without touching the network:

| Line | Source |
|---|---|
| Project name, stack, git | `project.yaml`, `repoState` |
| Last scan: when, open counts by severity, unverifiable count, verdict | `FindingsStore.latest()`, `verdict()` |
| Websites and APIs (env) | `project.yaml` targets |
| Servers (env) and collector output state: none / fresh / stale | `project.yaml` hosts, `SnapshotStore.latest`, `snapshotFreshness` |
| Accepted risks, and the soonest expiry | `loadExceptions`, `activeException` |
| Lessons waiting for review | `pendingLessons` |
| Checklist exported | `.secagent/reports/checklist.md` exists |
| Settings changed since the last scan | `project.yaml` modified after the last scan's `scanned_at` |

```
secagent · my-shop  (Next.js, git)

  Last scan   2 days ago · Needs attention: 1 high, 2 medium · 1 could not be checked
  Websites    shop.example.com (prod)
  Servers     web-1 (prod) · no collector output yet
  Accepted    1 risk, expires in 5 days
```

An invalid `project.yaml` shows the error and how to fix it, and exits 1, as the wizard does today.

### 4.2 Suggested next step

`suggestNext(status)` applies these rules in order; the first match wins:

1. Never scanned: run the first scan.
2. A listed server has no collector output, or it is stale: add that server's collector output.
3. Open critical or high findings: see what to fix first.
4. An accepted risk expires within 7 days: open "Accepted risks" (it says which one, and that it counts as open again after that date).
5. The last scan is older than 7 days, or the settings changed since: scan again.
6. The checklist has not been exported: review what the scan can't see.
7. Otherwise: nothing pressing, scan again after the next deploy.

Each suggestion carries a one-line reason shown under the status ("Next: add web-1's collector output, so I can check its SSH, nginx and packages").

### 4.3 Menu

The suggested action comes first, marked `(suggested)`. Items appear only when they apply: a code-only project with nothing pending sees nine, a project with servers and pending lessons at most twelve.

| Item | Shown when | Does (existing code it calls) |
|---|---|---|
| See what to fix first | a scan exists with open findings | `topFixes`; pick one to see what was found, why it matters, the fix and the evidence id |
| Scan again | always (first item before any scan: "Run the first scan") | Same session with consent: `scanWithProgress` with the session plan. Otherwise: `askPlan` starting at "again" (asks consent). Then the report is written and `showResult` runs, as today |
| Open the report | a report exists | PDF or HTML with `openWithSystem`; prints the Markdown path |
| Review what the scan can't see | always | Checklist hand-off (4.4) |
| Add a server's collector output | servers listed | Pick a server; offer to write the collector (`makeCollector`), print how to run it, then the existing `askSnapshot` question; store with `SnapshotStore.add` |
| Accepted risks | open findings or accepted risks | Lists accepted risks (finding, owner, reason, expiry, from `loadExceptions`), then offers "Accept the risk of a finding" when there are open findings: existing `acceptFromMenu`, then a rescan, as today |
| Check a scanner's CVE claim | servers listed | Pick a server, enter a CVE id; `verifyClaim`, printed with `formatClaim` (same as `secagent verify`) |
| Review lessons an AI assistant proposed | pending lessons | Existing `reviewLessons` |
| Connect an AI assistant | always | The `mcp setup` text, then what to ask the assistant |
| Settings and setup | always | Sub-menu: change the settings (`askPlan` at "change"), start over (`askPlan` at "fresh"), check this machine (`doctor()`, printed as `secagent doctor` prints it) |
| How secagent works | always | The guides (6.3) |
| Exit | always | Exit 0 |

`askPlan` gets a `start` option (`again` / `change` / `fresh`) in place of its "already set up" question, which the home screen replaces.

### 4.4 Checklist hand-off

1. Suggest areas from the project: websites or APIs listed → `surface`, `auth`, `input`; always `secrets`; servers listed or CI files present (`.github/workflows`, `.gitlab-ci.yml`) → `infra`. The person can change the selection (multiselect).
2. Write `renderChecklist(selectAreas(...), latest scan)` to `.secagent/reports/checklist.md`. `reports/` is already git-ignored.
3. Say how to work through it:
   ```
   I wrote 31 checks to .secagent/reports/checklist.md: things only someone reading the code can decide.

   Work through them with:
     • Claude Code:     /security-review
     • Another AI:      "Work through .secagent/reports/checklist.md against this code.
                         For each item say pass, fail or unknown, cite file:line, fails first."
     • By hand:         open the file
   Their answers are a review, not scan results; the scan's findings do not change.
   ```

Answers are not recorded. That is a possible follow-up, not part of this work.

### 4.5 Errors

An action that fails (an unreadable or invalid collector file, a malformed CVE id, an advisory source that cannot be reached, a `KbError`) prints the message in plain words and returns to the home screen; it never exits. The errors the wizard handles today (`ProjectConfigError`, `ScopeError`, `CatalogError`, `ObservationError`) keep their current handling. Ctrl+C exits with 130, as today.

## 5. Agent voice

The agent feel comes from how secagent talks, not from a model. All home-screen and intro text follows these rules:

- **First person, plain words.** "I found 3 things to fix", not "3 findings detected".
- **Say what was noticed, then why it matters, then what to do.** "web-1 has no collector output, so I could not check its SSH, nginx or packages. Want to add it now?"
- **Ask before acting.** Anything that probes, writes a file outside `.secagent/reports/` or accepts a risk is a question first.
- **Narrate while working.** The existing live scan progress stays as it is; before it starts, one line says what is about to happen ("Checking 2 websites and your code: 21 checks").
- **Sum up at the end.** After every action, one line saying what changed and what is next ("Stored web-1's collector output. Next: scan again to check it.").
- **Honest about limits.** Something that could not be checked is "I could not check", never "passed".

Command output for scripts and CI (`scan`, `verify`, `report` and so on) does not change.

## 6. Help

### 6.1 Command registry

`src/help/commands.ts` holds, for each command: name, group, one-line summary, usage line, option descriptions, 1 to 3 examples and "see also". The option objects each `runX` passes to `parseArgs` move, unchanged, into named constants in `cli.ts`, so a test can check that the registry documents exactly the options each parser accepts. Parsing behaviour does not change.

### 6.2 `secagent help` (also `-h`, `--help`, and `secagent` off a terminal)

```
secagent · finds what an attacker would hit first in your project, and how to fix it

Start here
  cd your-project && secagent       guided setup and scan, then a home screen with next steps

How it goes
  1. secagent                         answer a few questions, confirm permission, scan
  2. Read "Fix first"                 full report in .secagent/reports/ (PDF, HTML, Markdown)
  3. Fix, then secagent → Scan again  shows what was fixed, what is new, what regressed
  4. Review what the scan can't see   secagent checklist, or /security-review in Claude Code

Commands
  Scan and report      start, scan, report
  Results              accept, checklist
  Servers              collector, snapshot add, verify, learn
  AI assistants        mcp setup, mcp
  Setup                doctor, init, version
  CI and maintainers   eval, kb review, kb index

Guides     secagent help <guide>     start · servers · ai · ci · safety
Details    secagent help <command>   or  secagent <command> --help
```

### 6.3 Command pages and guides

- `secagent help <command>` and `secagent <command> --help` / `-h` print the command page: summary, usage, every option with its description, examples, see also. For `snapshot add`, `mcp setup`, `kb review` and `kb index`, both `secagent help snapshot` and `secagent snapshot --help` work.
- `--help` is handled before the command runs, so it never scans, writes or connects.
- Guides (`src/help/topics.ts`) are short numbered steps for jobs that take more than one command:
  - `start`: first scan to report, and what to do with the report.
  - `servers`: write the collector, read it, run it on the server, bring the output back, add it, scan.
  - `ai`: connect Claude Code or another MCP client, and what to ask it.
  - `ci`: `secagent scan --only code --fail-on high`, with a workflow example.
  - `safety`: what secagent touches and what it never does.
- The home screen's "How secagent works" lists the guides and prints the chosen one.

### 6.4 Errors that guide

- An unknown command prints `Unknown command "chekclist". Did you mean "checklist"?` (closest name by edit distance, when one is close) and `Run secagent help to see every command.` It no longer prints the whole usage text.
- A bad option or missing argument prints the existing message plus the command's usage line and `secagent help <command>`.
- Exit codes do not change.

## 7. Code layout

| File | Change |
|---|---|
| `src/help/commands.ts` | New: command registry |
| `src/help/topics.ts` | New: the five guides |
| `src/help/render.ts` | New: overview, command page, guide, "did you mean" |
| `src/home/status.ts` | New: `projectStatus(dir, now)`, local reads only |
| `src/home/next.ts` | New: `suggestNext(status)`, pure |
| `src/home/actions.ts` | New: fix-first detail, add collector output, CVE claim, checklist hand-off, connect AI, settings sub-menu |
| `src/home/run.ts` | New: the home loop |
| `src/wizard/run.ts` | Intro screen; after the first scan, hands over to the home loop. `scanWithProgress`, `showResult`, `acceptFromMenu`, `reviewLessons`, `openWithSystem` are exported for the home screen; the end-of-run menu moves to the home screen |
| `src/wizard/questions.ts` | `askPlan` takes `start` instead of asking "already set up"; `askSnapshot` exported |
| `src/cli.ts` | Option constants, `help <x>`, `--help` interception, did-you-mean; `mcpSetup` returns its lines so the CLI and the home screen share them |

## 8. Testing

- `suggestNext`: one case per rule, plus the priority between rules.
- `projectStatus`: built from temp projects (never scanned; scanned; server without collector output; stale collector output; expiring accepted risk; settings changed after the scan).
- Home loop with `ScriptedPrompter`: the suggested item is first; conditional items are hidden when they do not apply; a failing action returns to the menu; Exit returns 0; a rescan in the same session does not ask consent again, and a new session does.
- Each action: calls the same function as its CLI command (same result for the same input: for example, the stored snapshot equals what `snapshot add` stores, and the checklist file equals `secagent checklist --area ... --out`).
- Help: every dispatched command has a registry entry; the registry's options equal each parser's options; `secagent <command> --help` exits 0 for every command and writes nothing; every guide renders; did-you-mean suggests the right command; the overview is checked with a snapshot.
- Secrets: home-screen and help output for the leaky fixture contain no planted secret value.
- Existing tests pass unchanged, apart from the wizard tests for the two moved menus.

## 9. Docs

- `README.md` "Use it": the home screen and `secagent help`.
- `docs/usage.md`: the home screen (status, suggested next step, menu), help and guides, and the "Every command" table pointing to `secagent help <command>`.
- `AGENTS.md`: layout rows for `src/home/` and `src/help/`.

## 10. Out of scope

- Recording checklist answers.
- A web UI or a full-screen terminal UI.
- Any AI model in secagent itself, or natural-language input.
- Changes to checks, scan, report, MCP tools or the playbook.
