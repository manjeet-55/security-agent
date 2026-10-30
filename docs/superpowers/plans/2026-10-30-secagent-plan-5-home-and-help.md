# Home Screen and Help Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make `secagent` feel like working with an agent (a home screen that knows where the project stands, suggests the next step and reaches every capability) and give it real help (`secagent help`, `help <command>`, `<command> --help`, guides, "did you mean"), as a UI layer only.

**Architecture:** New `src/help/` (command registry, guides, rendering) and `src/home/` (status from local files, fixed next-step rules, menu actions, the home loop). Wizard helpers move unchanged from `src/wizard/run.ts` to `src/wizard/steps.ts` so the home screen can reuse them without an import cycle. Every home action calls the same function its CLI command calls. The CLI's parser options move unchanged into an `OPTIONS` constant so a test can hold the help text to them.

**Tech Stack:** TypeScript (ESM, NodeNext, `strict`, `noUncheckedIndexedAccess`), Node 20.19+, `node:util` `parseArgs`, vitest. No new dependencies.

**Spec:** [docs/superpowers/specs/2026-10-30-secagent-home-and-help-design.md](../specs/2026-10-30-secagent-home-and-help-design.md)

## Global Constraints

- UI layer only: the engine, checks, scope guard, consent, evidence, findings, report, every CLI command's options and output, the MCP server and the playbook do not change.
- Every home-screen action calls the same function its CLI command calls, with the same arguments.
- No AI model, no randomness: the same project state gives the same screen and suggestion.
- No network before consent; the home screen's status reads local files only.
- Consent works as today: a rescan in the same session reuses that session's consent; a new session asks again; accepting a risk triggers a rescan.
- Secret values never appear in output.
- No new runtime or dev dependencies.
- Existing tests pass unchanged, except: the wizard tests for the first run's intro question and the two moved menus (`test/wizard/run.test.ts`, the "already set up" tests in `test/wizard/questions.test.ts`, the guided-scan answers in `test/cli.test.ts` and `test/demo.test.ts`).
- Match the surrounding code: terse comments that say why, no dead code, `...(x ? { x } : {})` for optional properties.
- Commits: conventional style. **No `Co-Authored-By` or AI attribution lines.**
- Before each commit: `npm run typecheck && npm test` must pass (about 40 s).

## File map

| File | Responsibility |
|---|---|
| `src/help/commands.ts` (new) | Command registry: name, group, summary, usage, options, examples, see also; `findCommand` |
| `src/help/topics.ts` (new) | The five guides |
| `src/help/render.ts` (new) | Overview, command page, guide, `renderHelp`, `didYouMean`, `unknownCommand` |
| `src/verify/format.ts` (new) | `formatClaim`, moved from `src/cli.ts` |
| `src/mcp/setup.ts` (new) | `mcpSetupLines`, the text of `secagent mcp setup`, moved from `src/cli.ts` |
| `src/doctor.ts` | add `formatDoctor`, the text of `secagent doctor`, moved from `src/cli.ts` |
| `src/cli.ts` | `OPTIONS`, `help`, `--help`, hints, did-you-mean |
| `src/home/status.ts` (new) | `projectStatus(dir, now)`, `checklistFile(dir)` |
| `src/home/next.ts` (new) | `suggestNext(status)`, `HomeAction` |
| `src/wizard/steps.ts` (new) | Wizard helpers moved from `run.ts`, plus `askDepsFor`, later `scanAndReport` |
| `src/wizard/questions.ts` | `start` option, `askSnapshot` and `collectorSteps` exported |
| `src/report/model.ts` | export `fixText` |
| `src/home/actions.ts` (new) | The home screen's actions |
| `src/home/run.ts` (new) | `runHome`, `renderStatus`, `menuFor` |
| `src/wizard/run.ts` | First-run intro, then the home screen |

---

### Task 1: Help content and rendering

**Files:**
- Create: `src/help/commands.ts`
- Create: `src/help/topics.ts`
- Create: `src/help/render.ts`
- Test: `test/help/render.test.ts`

**Interfaces:**
- Consumes: nothing.
- Produces:
  - `COMMAND_GROUPS: readonly CommandGroup[]`, `COMMANDS: readonly CommandHelp[]`, `findCommand(words: readonly string[]): CommandHelp | undefined`
  - `interface CommandHelp { name: string; group: CommandGroup; summary: string; usage: string; options: readonly OptionHelp[]; examples: ReadonlyArray<{ command: string; note: string }>; seeAlso: readonly string[] }`, `interface OptionHelp { name: string; value?: string; description: string }`
  - `GUIDES: readonly Guide[]`, `interface Guide { name: string; title: string; body: string }`
  - `renderOverview(): string`, `renderCommand(c: CommandHelp): string`, `renderGuide(g: Guide): string`, `renderHelp(words: readonly string[]): { ok: boolean; text: string }`, `didYouMean(word: string): string | undefined`, `unknownCommand(word: string): string`

- [ ] **Step 1: Write the failing test**

Create `test/help/render.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { COMMAND_GROUPS, COMMANDS, findCommand } from '../../src/help/commands.js';
import { didYouMean, renderHelp, renderOverview, unknownCommand } from '../../src/help/render.js';
import { GUIDES } from '../../src/help/topics.js';

describe('help', () => {
  it('the overview starts with how to begin, lists every group, command and guide, and keeps the usage line', () => {
    const text = renderOverview();
    expect(text).toContain('Usage: secagent <command> [options]');
    expect(text.indexOf('Start here')).toBeLessThan(text.indexOf('Commands'));
    for (const g of COMMAND_GROUPS) expect(text).toContain(g);
    for (const c of COMMANDS) expect(text).toContain(c.name);
    for (const g of GUIDES) expect(text).toContain(g.name);
  });

  it('a command page has the summary, usage, every option and the examples', () => {
    const { ok, text } = renderHelp(['scan']);
    expect(ok).toBe(true);
    expect(text).toMatch(/^secagent scan · /);
    expect(text).toContain('secagent scan [--dir <path>] [--only <groups>] [--fail-on <severity>]');
    expect(text).toContain('--fail-on <severity>');
    expect(text).toContain('--no-ai');
    expect(text).toContain('secagent scan --only code --fail-on high');
    expect(text).toContain('See also');
  });

  it('finds sub-commands by one or two words', () => {
    expect(findCommand(['snapshot'])?.name).toBe('snapshot add');
    expect(findCommand(['snapshot', 'add'])?.name).toBe('snapshot add');
    expect(findCommand(['mcp'])?.name).toBe('mcp');
    expect(findCommand(['mcp', 'setup'])?.name).toBe('mcp setup');
    expect(findCommand(['kb'])?.name).toBe('kb review');
    expect(findCommand(['kb', 'index'])?.name).toBe('kb index');
    expect(findCommand(['accept', 'code-secrets-working-tree@code'])?.name).toBe('accept');
    expect(findCommand(['nope'])).toBeUndefined();
  });

  it('prints a guide by name, and says what is wrong for a name that is neither', () => {
    expect(renderHelp(['servers'])).toMatchObject({ ok: true, text: expect.stringContaining('sudo sh collect.sh > web-1.json') });
    const bad = renderHelp(['chekclist']);
    expect(bad.ok).toBe(false);
    expect(bad.text).toContain('Did you mean "checklist"?');
  });

  it('suggests the closest command or guide for a likely typo, and nothing for a far one', () => {
    expect(didYouMean('chekclist')).toBe('checklist');
    expect(didYouMean('scna')).toBe('scan');
    expect(didYouMean('serevrs')).toBe('servers');
    expect(didYouMean('nope')).toBeUndefined();
    expect(unknownCommand('scna')).toBe('Unknown command "scna". Did you mean "scan"?\nRun secagent help to see every command and guide.');
    expect(unknownCommand('nope')).toBe('Unknown command "nope".\nRun secagent help to see every command and guide.');
  });

  it('every page is complete, names are unique, and every "see also" leads somewhere', () => {
    const names = COMMANDS.map((c) => c.name);
    expect(new Set(names).size).toBe(names.length);
    for (const c of COMMANDS) {
      expect(c.usage.startsWith(`secagent ${c.name}`)).toBe(true);
      expect(c.examples.length).toBeGreaterThan(0);
      for (const s of c.seeAlso) {
        const [first = '', second] = s.split(' ');
        if (first === 'help') expect(GUIDES.map((g) => g.name)).toContain(second);
        else expect(names).toContain(s);
      }
    }
    // A guide named like a command would make `secagent help <name>` ambiguous.
    for (const g of GUIDES) expect(names.map((n) => n.split(' ')[0])).not.toContain(g.name);
  });
});
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run test/help/render.test.ts`
Expected: FAIL, `Cannot find module '../../src/help/commands.js'` (or similar).

- [ ] **Step 3: Write `src/help/commands.ts`**

```ts
/** What `secagent help` says about each command. Its options must match what the command's parser takes (test/cli.test.ts checks). */
export const COMMAND_GROUPS = ['Scan and report', 'Results', 'Servers', 'AI assistants', 'Setup', 'CI and maintainers'] as const;
export type CommandGroup = (typeof COMMAND_GROUPS)[number];

export interface OptionHelp {
  /** The long flag without dashes, as the parser names it. */
  name: string;
  /** Placeholder for the value, e.g. "<path>"; absent for a flag without one. */
  value?: string;
  description: string;
}

export interface CommandHelp {
  /** "scan", or two words for a sub-command: "snapshot add". */
  name: string;
  group: CommandGroup;
  summary: string;
  usage: string;
  options: readonly OptionHelp[];
  examples: ReadonlyArray<{ command: string; note: string }>;
  /** Other commands ("report") or guides ("help servers"). */
  seeAlso: readonly string[];
}

const DIR: OptionHelp = { name: 'dir', value: '<path>', description: 'project folder (default: the current folder)' };

export const COMMANDS: readonly CommandHelp[] = [
  {
    name: 'start',
    group: 'Scan and report',
    summary: 'The guided scan: set up and scan on the first run, then a home screen with where the project stands and what to do next (what `secagent` runs on a terminal)',
    usage: 'secagent start [--dir <path>]',
    options: [DIR],
    examples: [{ command: 'secagent', note: 'in your project folder: set up and scan, or open the home screen' }],
    seeAlso: ['scan', 'help first-scan'],
  },
  {
    name: 'scan',
    group: 'Scan and report',
    summary: 'Run every check against the code, websites and servers in project.yaml and write the report, without questions (for scripts and CI)',
    usage: 'secagent scan [--dir <path>] [--only <groups>] [--fail-on <severity>]',
    options: [
      DIR,
      { name: 'only', value: '<groups>', description: 'run only code, web or host (repeat, or separate with commas); the rest of the last scan is kept' },
      { name: 'fail-on', value: '<severity>', description: 'exit 1 when an open finding is at this severity or above: critical, high, medium, low or info' },
      { name: 'no-ai', description: 'accepted and ignored: a scan never uses AI' },
    ],
    examples: [
      { command: 'secagent scan', note: 'scan everything listed in project.yaml' },
      { command: 'secagent scan --only code --fail-on high', note: 'in CI: fail on a high or critical finding in the code' },
    ],
    seeAlso: ['report', 'init', 'help ci'],
  },
  {
    name: 'report',
    group: 'Scan and report',
    summary: 'Write the report of the latest scan again, without scanning (.secagent/reports/latest.md, .pdf and .html)',
    usage: 'secagent report [--dir <path>]',
    options: [DIR],
    examples: [{ command: 'secagent report', note: 'after upgrading secagent, to get the newest report layout' }],
    seeAlso: ['scan'],
  },
  {
    name: 'accept',
    group: 'Results',
    summary: "Accept the risk of an open finding until a date: a person's decision, listed in the report under Accepted risks",
    usage: 'secagent accept <finding-id> --owner <name> --reason <text> --until <YYYY-MM-DD> [--dir <path>]',
    options: [
      DIR,
      { name: 'owner', value: '<name>', description: 'who accepts the risk' },
      { name: 'reason', value: '<text>', description: 'why it is acceptable for now' },
      { name: 'until', value: '<YYYY-MM-DD>', description: 'last day it holds (at most a year); after that it counts as open again' },
    ],
    examples: [
      {
        command: "secagent accept code-secrets-working-tree@code --owner Priya --reason 'rotating the key next sprint' --until 2026-12-15",
        note: 'the finding id is in the report and in .secagent/findings/latest.json',
      },
    ],
    seeAlso: ['scan', 'report'],
  },
  {
    name: 'checklist',
    group: 'Results',
    summary: 'Print the review checklist: what to check in the code and configuration that the scan cannot decide',
    usage: 'secagent checklist [--area <area>] [--out <file>] [--dir <path>]',
    options: [
      DIR,
      { name: 'area', value: '<area>', description: 'surface, auth, input, secrets or infra (repeatable); default: all of them' },
      { name: 'out', value: '<file>', description: 'write it to a file instead of printing it' },
    ],
    examples: [{ command: 'secagent checklist --area auth --area input --out review.md', note: 'give review.md to your AI assistant, or work through it yourself' }],
    seeAlso: ['help ai'],
  },
  {
    name: 'collector',
    group: 'Servers',
    summary: 'Print the read-only script to run on a server (stdout) and how to run it (stderr)',
    usage: 'secagent collector --host <name> [--out <file>] [--dir <path>]',
    options: [
      DIR,
      { name: 'host', value: '<name>', description: 'a server listed in project.yaml' },
      { name: 'out', value: '<file>', description: 'write the script to a file' },
    ],
    examples: [{ command: 'secagent collector --host web-1 --out collect.sh', note: 'then read collect.sh, copy it to web-1 and run it there' }],
    seeAlso: ['snapshot add', 'help servers'],
  },
  {
    name: 'snapshot add',
    group: 'Servers',
    summary: "Check and store a server's collector output, so the next scan can check that server",
    usage: 'secagent snapshot add --host <name> <file> [--dir <path>]',
    options: [DIR, { name: 'host', value: '<name>', description: 'the server the output came from' }],
    examples: [{ command: 'secagent snapshot add --host web-1 web-1.json', note: 'web-1.json is what the collector printed on web-1' }],
    seeAlso: ['collector', 'help servers'],
  },
  {
    name: 'verify',
    group: 'Servers',
    summary: "Is a scanner's CVE claim true for this server? Decided from its installed packages and the distro's own advisories",
    usage: 'secagent verify --host <name> --cve <CVE-id> [--package <name>] [--json] [--dir <path>]',
    options: [
      DIR,
      { name: 'host', value: '<name>', description: 'a server with stored collector output' },
      { name: 'cve', value: '<CVE-id>', description: 'e.g. CVE-2024-6387' },
      { name: 'package', value: '<name>', description: 'the package the scanner named, if any' },
      { name: 'json', description: 'print the result as JSON' },
    ],
    examples: [{ command: 'secagent verify --host web-1 --cve CVE-2024-6387', note: 'fixed_in_installed means the scanner was wrong: the fix is backported' }],
    seeAlso: ['snapshot add', 'learn'],
  },
  {
    name: 'learn',
    group: 'Servers',
    summary: "Refresh CISA's known-exploited list and the package advisories for every server's stored collector output",
    usage: 'secagent learn [--dir <path>]',
    options: [DIR],
    examples: [{ command: 'secagent learn', note: 'before working on a machine that will be offline' }],
    seeAlso: ['verify'],
  },
  {
    name: 'mcp setup',
    group: 'AI assistants',
    summary: 'Print the exact command that connects Claude Code or another AI assistant to this project',
    usage: 'secagent mcp setup [--dir <path>]',
    options: [DIR],
    examples: [{ command: 'secagent mcp setup', note: 'then ask your assistant: "Run a security review of this project"' }],
    seeAlso: ['mcp', 'help ai'],
  },
  {
    name: 'mcp',
    group: 'AI assistants',
    summary: 'Serve this project to an AI assistant over MCP (stdio); your assistant starts this, not you',
    usage: 'secagent mcp [--dir <path>]',
    options: [DIR],
    examples: [{ command: 'claude mcp add secagent -- secagent mcp --dir .', note: 'what mcp setup prints for Claude Code' }],
    seeAlso: ['mcp setup', 'help ai'],
  },
  {
    name: 'doctor',
    group: 'Setup',
    summary: 'Check this machine and project for what usually goes wrong, and say how to fix each problem',
    usage: 'secagent doctor [--offline] [--dir <path>]',
    options: [DIR, { name: 'offline', description: 'skip the check that the advisory database can be reached' }],
    examples: [{ command: 'secagent doctor', note: 'the first thing to run when something does not work' }],
    seeAlso: ['help first-scan'],
  },
  {
    name: 'init',
    group: 'Setup',
    summary: 'Create .secagent/ and project.yaml without questions (for scripts; on a terminal, `secagent` asks instead)',
    usage: 'secagent init [--name <name>] [--scan-label <label>] [--target <spec>]... [--host <spec>]... [--dir <path>]',
    options: [
      DIR,
      { name: 'name', value: '<name>', description: 'project name (default: the folder name)' },
      { name: 'scan-label', value: '<label>', description: 'the network you scan from, e.g. office or ci' },
      { name: 'target', value: '<id=https://host,web|api,env>', description: 'a website or API to check (repeatable)' },
      { name: 'host', value: '<name=address,env>', description: 'a server to check (repeatable)' },
    ],
    examples: [{ command: 'secagent init --scan-label ci --target shop=https://shop.example.com,web,prod', note: 'set up a project in a pipeline' }],
    seeAlso: ['scan'],
  },
  {
    name: 'version',
    group: 'Setup',
    summary: 'Print the version',
    usage: 'secagent version',
    options: [],
    examples: [{ command: 'secagent --version', note: 'the same' }],
    seeAlso: [],
  },
  {
    name: 'help',
    group: 'Setup',
    summary: 'Show the overview, the page for one command, or a step-by-step guide',
    usage: 'secagent help [<command> | <guide>]',
    options: [],
    examples: [
      { command: 'secagent help servers', note: 'how to check a server, step by step' },
      { command: 'secagent scan --help', note: 'the page for one command' },
    ],
    seeAlso: [],
  },
  {
    name: 'eval',
    group: 'CI and maintainers',
    summary: 'Compare the latest scan with a file of expected statuses; exit 1 on any difference',
    usage: 'secagent eval <expected.yaml> [--dir <path>]',
    options: [DIR],
    examples: [{ command: 'secagent eval expected.yaml', note: 'expected.yaml: findings: { code-secrets-working-tree@code: open }' }],
    seeAlso: ['scan'],
  },
  {
    name: 'kb review',
    group: 'CI and maintainers',
    summary: 'List lessons an AI assistant proposed; approve or reject one',
    usage: 'secagent kb review [--approve <id> --by <name>] [--reject <id>] [--dir <path>]',
    options: [
      DIR,
      { name: 'approve', value: '<id>', description: 'approve this lesson (with --by)' },
      { name: 'by', value: '<name>', description: 'who approves it' },
      { name: 'reject', value: '<id>', description: 'reject and delete this lesson' },
    ],
    examples: [{ command: 'secagent kb review', note: 'list what is waiting' }],
    seeAlso: ['kb index'],
  },
  {
    name: 'kb index',
    group: 'CI and maintainers',
    summary: 'Regenerate knowledge/INDEX.md from the lessons, checks and checklists (for secagent maintainers)',
    usage: 'secagent kb index',
    options: [],
    examples: [{ command: 'secagent kb index', note: 'after adding a check or a checklist item' }],
    seeAlso: ['kb review'],
  },
];

/** The command named by the first one or two words: "snapshot add", "scan"; a bare "kb" or "snapshot" finds its first sub-command. */
export function findCommand(words: readonly string[]): CommandHelp | undefined {
  const [first = '', second] = words;
  return (
    (second !== undefined ? COMMANDS.find((c) => c.name === `${first} ${second}`) : undefined) ??
    COMMANDS.find((c) => c.name === first) ??
    COMMANDS.find((c) => c.name.startsWith(`${first} `))
  );
}
```

- [ ] **Step 4: Write `src/help/topics.ts`**

```ts
/** Step-by-step guides for jobs that take more than one command: `secagent help <guide>` and the home screen's "How secagent works". */
export interface Guide {
  name: string;
  title: string;
  /** Paragraphs and numbered steps, as printed. */
  body: string;
}

export const GUIDES: readonly Guide[] = [
  {
    name: 'first-scan',
    title: 'Your first scan',
    body: `1. Open a terminal in your project folder and run:  secagent
2. Answer the questions: the project name, what to check (code, websites, servers), the addresses, where you are scanning from.
3. Confirm that you own the systems or have written permission to test them. Nothing on the network is touched before this.
4. Watch the checks run: ✓ passed, ✗ failed, ? could not check.
5. Read the verdict and "Fix first". The full report is in .secagent/reports/ as PDF, HTML and Markdown.
6. Fix the top item, run secagent again and choose "Scan again". The report then says what was fixed, what is new and what regressed.

Every later run of secagent opens the home screen: where the project stands and the step I suggest next.`,
  },
  {
    name: 'servers',
    title: 'Checking a server',
    body: `I never log in to your servers. You run a read-only script on each one and bring its output back.

1. List the server: run secagent, choose "Settings and setup" → "Change what is checked", tick Servers, enter its name and address.
2. Get the script: home screen → "Add a server's collector output", or  secagent collector --host web-1 --out collect.sh
3. Read the script, copy it to the server and run it there:  sudo sh collect.sh > web-1.json
4. Bring web-1.json back and add it: home screen → "Add a server's collector output", or  secagent snapshot add --host web-1 web-1.json
5. Scan again. I check SSH and nginx settings, reachable admin and database ports, pending security updates and packages with advisories.

Collector output older than 7 days is stale: run the script again.
To check a scanner's CVE claim against the server's real packages:  secagent verify --host web-1 --cve CVE-2024-6387`,
  },
  {
    name: 'ai',
    title: 'Using secagent with an AI assistant',
    body: `An AI assistant (Claude Code, Cursor, any MCP client) can run the scan, explain the findings and help fix them. I still decide every status; the assistant cannot change what is probed or accept a risk.

1. Set the project up once: run secagent in the folder and confirm the websites and servers.
2. Print the connect command:  secagent mcp setup   (or home screen → "Connect an AI assistant")
3. Run what it prints, e.g.  claude mcp add secagent -- secagent mcp --dir /path/to/project
4. Ask your assistant: "Run a security review of this project". In Claude Code with the secagent plugin:  /security-review
5. For what the scan cannot see, the assistant works through the review checklist with your code and labels its answers as its own review.`,
  },
  {
    name: 'ci',
    title: 'Running secagent in CI',
    body: `The code checks need nothing from your websites or servers, so they suit every pull request.

1. Commit .secagent/project.yaml (run secagent once on your machine, or  secagent init  in the pipeline).
2. Check out the full git history (the secrets-in-history check needs it) and run:
     secagent scan --only code --fail-on high
   It exits 1 when an open finding is high or critical, and writes the report to .secagent/reports/.
3. Keep .secagent/reports/latest.pdf as a build artifact.

docs/usage.md (Recipes, "CI gate on every pull request") has a complete GitHub Actions workflow.`,
  },
  {
    name: 'safety',
    title: 'What secagent touches, and what it never does',
    body: `• Scope: I only probe the websites and servers listed in .secagent/project.yaml, and refuse any other address, including one a page redirects to.
• Permission: nothing on the network is touched until you confirm you own the systems or have written permission to test them. Your yes is stored outside the project (~/.config/secagent/consent.json).
• Read-only: GET and HEAD requests, TLS handshakes and TCP connection tests. No logins, no form posts, no guessing passwords.
• Private addresses need an extra yes; cloud metadata addresses (169.254.169.254) are never probed.
• Your data: code and files stay on your machine. Only package names and versions go to public advisory databases (OSV, Ubuntu Security, CISA).
• Secrets: output shows the file, line and a short fingerprint, never the value.
• Servers: I never log in. You run a read-only script there and bring its output back.`,
  },
];
```

- [ ] **Step 5: Write `src/help/render.ts`**

```ts
import { COMMAND_GROUPS, COMMANDS, findCommand, type CommandHelp, type OptionHelp } from './commands.js';
import { GUIDES, type Guide } from './topics.js';

/** `secagent help`: where to start, the usual steps, the commands by task, and where to read more. */
export function renderOverview(): string {
  return [
    'secagent · finds what an attacker would hit first in your project, and how to fix it',
    '',
    'Usage: secagent <command> [options]',
    '',
    'Start here',
    '  cd your-project && secagent       guided setup and scan, then a home screen with next steps',
    '',
    'How it goes',
    '  1. secagent                         answer a few questions, confirm permission, scan',
    '  2. Read "Fix first"                 full report in .secagent/reports/ (PDF, HTML, Markdown)',
    '  3. Fix, then secagent → Scan again  shows what was fixed, what is new, what regressed',
    "  4. Review what the scan can't see   secagent checklist, or /security-review in Claude Code",
    '',
    'Commands',
    ...COMMAND_GROUPS.map((g) => `  ${g.padEnd(20)} ${COMMANDS.filter((c) => c.group === g).map((c) => c.name).join(', ')}`),
    '',
    `Guides     secagent help <guide>     ${GUIDES.map((g) => g.name).join(' · ')}`,
    'Details    secagent help <command>   or  secagent <command> --help',
  ].join('\n');
}

function flag(o: OptionHelp): string {
  return `--${o.name}${o.value ? ` ${o.value}` : ''}`;
}

/** One command's page: what it does, usage, options, examples, see also. */
export function renderCommand(c: CommandHelp): string {
  const width = Math.max(0, ...c.options.map((o) => flag(o).length)) + 2;
  return [
    `secagent ${c.name} · ${c.summary}`,
    '',
    'Usage',
    `  ${c.usage}`,
    ...(c.options.length > 0 ? ['', 'Options', ...c.options.map((o) => `  ${flag(o).padEnd(width)}${o.description}`)] : []),
    '',
    'Examples',
    ...c.examples.flatMap((e) => [`  ${e.command}`, `      ${e.note}`]),
    ...(c.seeAlso.length > 0 ? ['', `See also   ${c.seeAlso.map((s) => `secagent ${s}`).join(' · ')}`] : []),
  ].join('\n');
}

export function renderGuide(g: Guide): string {
  return `${g.title}\n\n${g.body}`;
}

/** `secagent help [words]`: the overview, a guide, or a command page; ok is false for a name that is neither. */
export function renderHelp(words: readonly string[]): { ok: boolean; text: string } {
  const [first] = words;
  if (first === undefined) return { ok: true, text: renderOverview() };
  const guide = GUIDES.find((g) => g.name === first);
  if (guide) return { ok: true, text: renderGuide(guide) };
  const command = findCommand(words);
  if (command) return { ok: true, text: renderCommand(command) };
  return { ok: false, text: notFound(`No command or guide called "${first}".`, first) };
}

export function unknownCommand(word: string): string {
  return notFound(`Unknown command "${word}".`, word);
}

function notFound(lead: string, word: string): string {
  const close = didYouMean(word);
  return `${lead}${close ? ` Did you mean "${close}"?` : ''}\nRun secagent help to see every command and guide.`;
}

/** The command or guide a mistyped word most likely meant, or nothing when none is close. */
export function didYouMean(word: string): string | undefined {
  const names = [...new Set([...COMMANDS.map((c) => c.name.split(' ')[0] ?? c.name), ...GUIDES.map((g) => g.name)])];
  const typed = word.toLowerCase();
  let best: { name: string; distance: number } | undefined;
  for (const name of names) {
    const distance = editDistance(typed, name);
    if (!best || distance < best.distance) best = { name, distance };
  }
  return best && best.distance <= (typed.length >= 5 ? 2 : 1) ? best.name : undefined;
}

/** Edits (insert, delete, change, swap two neighbours) that turn a into b. */
function editDistance(a: string, b: string): number {
  const cols = b.length + 1;
  const d = new Array<number>((a.length + 1) * cols).fill(0);
  const at = (i: number, j: number): number => d[i * cols + j] ?? 0;
  for (let i = 0; i <= a.length; i += 1) d[i * cols] = i;
  for (let j = 0; j <= b.length; j += 1) d[j] = j;
  for (let i = 1; i <= a.length; i += 1) {
    for (let j = 1; j <= b.length; j += 1) {
      let v = Math.min(at(i - 1, j) + 1, at(i, j - 1) + 1, at(i - 1, j - 1) + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (i > 1 && j > 1 && a[i - 1] === b[j - 2] && a[i - 2] === b[j - 1]) v = Math.min(v, at(i - 2, j - 2) + 1);
      d[i * cols + j] = v;
    }
  }
  return at(a.length, b.length);
}
```

- [ ] **Step 6: Run the test to verify it passes**

Run: `npx vitest run test/help/render.test.ts`
Expected: PASS (6 tests).

- [ ] **Step 7: Typecheck, full tests, commit**

```bash
npm run typecheck && npm test
git add src/help test/help
git commit -m "feat(help): command registry, guides and help rendering"
```

---

### Task 2: CLI help, per-command `--help` and guiding errors

**Files:**
- Create: `src/verify/format.ts`
- Create: `src/mcp/setup.ts`
- Modify: `src/doctor.ts` (add `formatDoctor`)
- Modify: `src/cli.ts`
- Test: `test/cli.test.ts`, `test/doctor.test.ts`

**Interfaces:**
- Consumes: `COMMANDS`, `findCommand`, `CommandHelp` from `src/help/commands.ts`; `renderCommand`, `renderHelp`, `renderOverview`, `unknownCommand` from `src/help/render.ts`.
- Produces:
  - `export const OPTIONS` in `src/cli.ts`: each command's `parseArgs` options, keyed by command name (`'kb review'`, `'snapshot add'`, `'mcp setup'` for sub-commands).
  - `formatClaim(r: ClaimResult): string[]` in `src/verify/format.ts`
  - `mcpSetupLines(dir: string): string[]` in `src/mcp/setup.ts`
  - `formatDoctor(lines: readonly DoctorLine[]): { lines: string[]; code: number }` in `src/doctor.ts`

- [ ] **Step 1: Write the failing tests**

In `test/cli.test.ts`, change the import of `../src/cli.js` to also take `OPTIONS`, and add an import of the registry:

```ts
import { formatScan, main, OPTIONS, parseHostSpec, parseTargetSpec, UsageError } from '../src/cli.js';
import { COMMANDS } from '../src/help/commands.js';
```

Append this `describe` block at the end of the file:

```ts
describe('help', () => {
  const COMMAND_WORDS = ['start', 'init', 'scan', 'report', 'accept', 'checklist', 'collector', 'snapshot', 'verify', 'learn', 'mcp', 'doctor', 'eval', 'kb', 'version', 'help'];

  it('help, --help and -h print the overview: where to start, the steps, the commands by task', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    for (const args of [['help'], ['--help'], ['-h']]) expect(await main(args)).toBe(0);
    expect(log).toHaveBeenCalledTimes(3);
    const text = String(log.mock.calls[0]?.[0]);
    expect(text).toContain('Start here');
    expect(text).toContain('Scan and report');
  });

  it('every command answers --help with its own page and runs nothing', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = await tempDir();
    for (const word of COMMAND_WORDS) {
      log.mockClear();
      expect(await main([word, '--help', '--dir', dir])).toBe(0);
      expect(String(log.mock.calls[0]?.[0])).toMatch(new RegExp(`^secagent ${word}`));
    }
    expect(existsSync(path.join(dir, '.secagent'))).toBe(false);
  });

  it('help <command> and help <guide> print that page; an unknown name exits 1 with a suggestion', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['help', 'snapshot', 'add'])).toBe(0);
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/^secagent snapshot add · /));
    expect(await main(['help', 'servers'])).toBe(0);
    expect(log).toHaveBeenCalledWith(expect.stringContaining('Checking a server'));
    expect(await main(['help', 'chekclist'])).toBe(1);
    expect(error).toHaveBeenCalledWith(expect.stringContaining('Did you mean "checklist"?'));
  });

  it('an unknown command suggests the closest one instead of printing every command', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['chekclist'])).toBe(1);
    expect(error).toHaveBeenCalledWith('Unknown command "chekclist". Did you mean "checklist"?\nRun secagent help to see every command and guide.');
    expect(error.mock.calls.flat().join('\n')).not.toContain('Scan and report');
  });

  it("a usage error points at the command's page; a bad option also shows its usage line", async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['init', '--bogus'])).toBe(1);
    expect(error).toHaveBeenCalledWith(expect.stringContaining('Usage: secagent init [--name <name>]'));
    expect(error).toHaveBeenCalledWith(expect.stringContaining('Run secagent help init for details.'));
    expect(await main(['accept', '--dir', await tempDir()])).toBe(1);
    expect(error).toHaveBeenCalledWith('Run secagent help accept for details.');
  });

  it("documents exactly the options each command's parser takes", () => {
    const parsers = OPTIONS as Record<string, Record<string, unknown>>;
    for (const c of COMMANDS) expect([c.name, c.options.map((o) => o.name).sort()]).toEqual([c.name, Object.keys(parsers[c.name] ?? {}).sort()]);
    for (const name of Object.keys(OPTIONS)) expect(COMMANDS.map((c) => c.name)).toContain(name);
  });
});
```

In `test/doctor.test.ts`, add `formatDoctor` to the import from `../src/doctor.js` and add inside its top-level `describe`:

```ts
  it('formatDoctor prints a mark per line with its fix below, a summary, and exit code 1 only on a failure', () => {
    expect(formatDoctor([{ level: 'ok', text: 'Node 22.0.0' }, { level: 'warn', text: 'No scan yet', fix: 'Run: secagent scan' }])).toEqual({
      lines: ['✓ Node 22.0.0', '! No scan yet', '    Run: secagent scan', '\nWorks, with 1 thing(s) worth a look.'],
      code: 0,
    });
    expect(formatDoctor([{ level: 'fail', text: 'Node 18.19.0 is too old', fix: 'Install Node 20.19 or newer (https://nodejs.org).' }]).code).toBe(1);
    expect(formatDoctor([{ level: 'ok', text: 'git is installed' }]).lines.at(-1)).toBe('\nAll good.');
  });
```

(If `test/doctor.test.ts` has no top-level `describe`, add the `it` at top level.)

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/cli.test.ts test/doctor.test.ts`
Expected: FAIL. `OPTIONS` and `formatDoctor` are not exported; `scan --help` fails with `Unknown option '--help'`.

- [ ] **Step 3: Move `formatClaim` to `src/verify/format.ts`**

Create `src/verify/format.ts`, with the function body moved unchanged from `src/cli.ts`:

```ts
import type { ClaimResult } from './claim.js';

/** What `secagent verify` prints for a verdict. */
export function formatClaim(r: ClaimResult): string[] {
  return [
    `${r.cve} on ${r.host}: ${r.verdict}${r.kev === true ? ' (CISA KEV: known exploited)' : ''}`,
    `  ${r.reason}`,
    ...r.packages.map(
      (p) => `  ${p.package}: installed ${p.installed ?? '-'}, distro status ${p.distro_status}${p.fixed ? `, fixed in ${p.fixed}` : ''} → ${p.verdict}`,
    ),
    ...(r.source_url ? [`  source: ${r.source_url}`] : []),
    ...(r.as_of ? [`  advisories as of ${r.as_of.slice(0, 10)}${r.stale ? ' (STALE: cached copy, source unreachable)' : ''}`] : []),
    `  evidence: ${r.evidence_id}`,
  ];
}
```

In `src/cli.ts`, delete `export function formatClaim(...) { ... }` and change the import `import { verifyClaim, type ClaimResult } from './verify/claim.js';` to:

```ts
import { verifyClaim } from './verify/claim.js';
import { formatClaim } from './verify/format.js';
```

- [ ] **Step 4: Move the `mcp setup` text to `src/mcp/setup.ts`**

Create `src/mcp/setup.ts`, moving the body of `mcpSetup` from `src/cli.ts` (same strings, same order):

```ts
import { existsSync, realpathSync } from 'node:fs';
import path from 'node:path';

/** What `secagent mcp setup` prints: the command that connects Claude Code or another AI client to this project folder. */
export function mcpSetupLines(dir: string): string[] {
  const entry = process.argv[1] ? realpathSync(process.argv[1]) : '';
  const onPath = (process.env.PATH ?? '').split(path.delimiter).some((d) => d !== '' && existsSync(path.join(d, 'secagent')));
  const command = onPath ? ['secagent'] : [process.execPath, entry];
  const shown = (xs: string[]) => xs.map((x) => (/\s/.test(x) ? JSON.stringify(x) : x)).join(' ');
  return [
    `Connect an AI client to ${dir}\n`,
    `Claude Code:\n  claude mcp add secagent -- ${shown([...command, 'mcp', '--dir', dir])}\n`,
    `Other clients (a JSON config such as .mcp.json):\n${JSON.stringify({ mcpServers: { secagent: { command: command[0], args: [...command.slice(1), 'mcp', '--dir', dir] } } }, null, 2)}\n`,
    'Then ask your assistant: "Run a security review of this project". It needs the folder set up first (run `secagent` here once).',
  ];
}
```

- [ ] **Step 5: Add `formatDoctor` to `src/doctor.ts`**

Append to `src/doctor.ts` (the text moves unchanged from `runDoctor` in `src/cli.ts`):

```ts
/** What `secagent doctor` prints, and its exit code: 1 when anything failed. */
export function formatDoctor(lines: readonly DoctorLine[]): { lines: string[]; code: number } {
  const mark = { ok: '✓', warn: '!', fail: '✗' } as const;
  const text = lines.flatMap((l) => [`${mark[l.level]} ${l.text}`, ...(l.fix ? [`    ${l.fix}`] : [])]);
  const fails = lines.filter((l) => l.level === 'fail').length;
  const warns = lines.filter((l) => l.level === 'warn').length;
  text.push(fails > 0 ? `\n${fails} problem(s) to fix.` : warns > 0 ? `\nWorks, with ${warns} thing(s) worth a look.` : '\nAll good.');
  return { lines: text, code: fails > 0 ? 1 : 0 };
}
```

- [ ] **Step 6: Rewire `src/cli.ts`**

6a. Imports. Change `import { existsSync, realpathSync } from 'node:fs';` to `import { realpathSync } from 'node:fs';`. Change `import { parseArgs } from 'node:util';` to `import { parseArgs, type ParseArgsConfig } from 'node:util';`. Change `import { doctor } from './doctor.js';` to `import { doctor, formatDoctor } from './doctor.js';`. Add:

```ts
import { findCommand, type CommandHelp } from './help/commands.js';
import { renderCommand, renderHelp, renderOverview, unknownCommand } from './help/render.js';
import { mcpSetupLines } from './mcp/setup.js';
```

6b. Replace the whole `const USAGE = \`...\`;` with:

```ts
/** Each command's options, exactly as its parser takes them. `secagent help` documents the same names (test/cli.test.ts checks). */
export const OPTIONS = {
  start: { dir: { type: 'string', default: '.' } },
  init: {
    dir: { type: 'string', default: '.' },
    name: { type: 'string' },
    'scan-label': { type: 'string' },
    target: { type: 'string', multiple: true },
    host: { type: 'string', multiple: true },
  },
  scan: {
    dir: { type: 'string', default: '.' },
    'no-ai': { type: 'boolean', default: false },
    only: { type: 'string', multiple: true },
    'fail-on': { type: 'string' },
  },
  report: { dir: { type: 'string', default: '.' } },
  accept: { dir: { type: 'string', default: '.' }, owner: { type: 'string' }, reason: { type: 'string' }, until: { type: 'string' } },
  checklist: { dir: { type: 'string', default: '.' }, area: { type: 'string', multiple: true }, out: { type: 'string' } },
  collector: { dir: { type: 'string', default: '.' }, host: { type: 'string' }, out: { type: 'string' } },
  'snapshot add': { dir: { type: 'string', default: '.' }, host: { type: 'string' } },
  verify: {
    dir: { type: 'string', default: '.' },
    host: { type: 'string' },
    cve: { type: 'string' },
    package: { type: 'string' },
    json: { type: 'boolean', default: false },
  },
  learn: { dir: { type: 'string', default: '.' } },
  'mcp setup': { dir: { type: 'string', default: '.' } },
  mcp: { dir: { type: 'string', default: '.' } },
  doctor: { dir: { type: 'string', default: '.' }, offline: { type: 'boolean', default: false } },
  eval: { dir: { type: 'string', default: '.' } },
  'kb review': { dir: { type: 'string', default: '.' }, approve: { type: 'string' }, reject: { type: 'string' }, by: { type: 'string' } },
} as const satisfies Record<string, NonNullable<ParseArgsConfig['options']>>;
```

(`as const satisfies` keeps `multiple: true` and `type: 'string'` literal, so `values` keeps the same types as with inline options; this was checked with `tsc`.)

6c. In every `parseArgs({ ... options: { ... } })` call, replace the inline object with the matching constant. The object each replaces is identical, so behaviour does not change:

| Function | New `options:` |
|---|---|
| `runInit` | `OPTIONS.init` |
| `runScan` | `OPTIONS.scan` |
| `runAccept` | `OPTIONS.accept` |
| `runEval` | `OPTIONS.eval` |
| `runKbReview` | `OPTIONS['kb review']` |
| `runChecklist` | `OPTIONS.checklist` |
| `runDoctor` | `OPTIONS.doctor` |
| `mcpSetup` | `OPTIONS['mcp setup']` |
| `runMcp` | `OPTIONS.mcp` |
| `runReport` | `OPTIONS.report` |
| `runCollector` | `OPTIONS.collector` |
| `runSnapshot` | `OPTIONS['snapshot add']` |
| `runVerify` | `OPTIONS.verify` |
| `runLearn` | `OPTIONS.learn` |
| `runStart` | `OPTIONS.start` |

6d. Replace the body of `runDoctor` after its `parseArgs` line with:

```ts
  const { lines, code } = formatDoctor(await doctor(path.resolve(values.dir), { now: deps.now ?? (() => new Date()), offline: values.offline }));
  for (const line of lines) console.log(line);
  return code;
```

6e. Replace `mcpSetup` with:

```ts
function mcpSetup(args: string[]): number {
  const { values } = parseArgs({ args, strict: true, options: OPTIONS['mcp setup'] });
  for (const line of mcpSetupLines(path.resolve(values.dir))) console.log(line);
  return 0;
}
```

6f. Add these helpers above `main`:

```ts
/** The page for `secagent <command> [sub-command] ...`: words before the options name it. */
function pageFor(command: string, rest: readonly string[]): CommandHelp | undefined {
  return findCommand([command, ...rest.filter((a) => !a.startsWith('-'))]);
}

/** Where to read more after a usage error: the command's page, and for a bad option its usage line too. */
function helpHint(command: string, rest: readonly string[], withUsage: boolean): string {
  const page = pageFor(command, rest);
  if (!page) return 'Run secagent help to see every command.';
  return `${withUsage ? `Usage: ${page.usage}\n` : ''}Run secagent help ${page.name} for details.`;
}

function runHelp(words: readonly string[]): number {
  const { ok, text } = renderHelp(words);
  if (ok) console.log(text);
  else console.error(text);
  return ok ? 0 : 1;
}
```

6g. In `main`, add the `--help` check as the first statement inside `try`, before `switch (command)`:

```ts
    // `<command> --help` shows that command's page and runs nothing.
    if (command !== undefined && (rest.includes('--help') || rest.includes('-h'))) {
      const page = pageFor(command, rest);
      if (page) {
        console.log(renderCommand(page));
        return 0;
      }
    }
```

Replace these three `switch` cases:

```ts
      case undefined:
        if (isTerminal(deps)) return await runStart(rest, deps);
        console.log(renderOverview());
        return 0;
```

```ts
      case 'help':
      case '--help':
      case '-h':
        return runHelp(rest);
      default:
        console.error(unknownCommand(command));
        return 1;
```

and the `catch` block with:

```ts
  } catch (e) {
    if (
      e instanceof UsageError ||
      e instanceof ProjectConfigError ||
      e instanceof CatalogError ||
      e instanceof ScopeError ||
      e instanceof KbError ||
      e instanceof EvalError ||
      e instanceof ObservationError
    ) {
      console.error(e.message);
      if (e instanceof UsageError && command !== undefined) console.error(helpHint(command, rest, false));
      return 1;
    }
    if (e instanceof TypeError && String((e as NodeJS.ErrnoException).code ?? '').startsWith('ERR_PARSE_ARGS')) {
      console.error(e.message);
      if (command !== undefined) console.error(helpHint(command, rest, true));
      return 1;
    }
    throw e;
  }
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `npx vitest run test/cli.test.ts test/doctor.test.ts test/help`
Expected: PASS, including the existing `prints usage with no command` (the overview keeps `Usage: secagent <command> [options]`), `kb needs the index subcommand` and `mcp setup prints a runnable command`.

- [ ] **Step 8: Typecheck, full tests, commit**

```bash
npm run typecheck && npm test
git add src/cli.ts src/doctor.ts src/verify/format.ts src/mcp/setup.ts test/cli.test.ts test/doctor.test.ts
git commit -m "feat(cli): secagent help, per-command --help, did-you-mean and usage hints"
```

---

### Task 3: Project status and the suggested next step

**Files:**
- Create: `src/home/status.ts`
- Create: `src/home/next.ts`
- Test: `test/home/status.test.ts`, `test/home/next.test.ts`

**Interfaces:**
- Consumes: existing `loadProject`, `FindingsStore`, `SnapshotStore`, `snapshotFreshness`, `loadExceptions`, `pendingLessons`, `verdict`, `repoState`.
- Produces:
  - `projectStatus(dir: string, now: Date): Promise<ProjectStatus>`, `checklistFile(dir: string): string`
  - `interface ProjectStatus { name: string; stack: string[]; git: boolean; lastScan?: LastScan; websites: Array<{ id: string; url: string; env: string }>; servers: ServerStatus[]; unscanned: string[]; accepted: AcceptedRisk[]; pendingLessons: number; checklistExported: boolean }`
  - `interface LastScan { at: string; ageDays: number; verdict: { tone: Tone; text: string }; open: Array<[Severity, number]>; urgent: number; unverifiable: number }`
  - `interface ServerStatus { name: string; address: string; env: string; collector: 'none' | 'fresh' | 'stale' }`
  - `interface AcceptedRisk { findingId: string; owner: string; reason: string; expires: string; daysLeft: number }`
  - `type HomeAction = 'fixes' | 'scan' | 'report' | 'checklist' | 'collector' | 'risks' | 'verify' | 'lessons' | 'ai' | 'settings' | 'help' | 'exit'`
  - `interface Suggestion { action: HomeAction; text: string; host?: string }`, `suggestNext(s: ProjectStatus): Suggestion`

- [ ] **Step 1: Write the failing tests**

Create `test/home/next.test.ts`:

```ts
import { describe, expect, it } from 'vitest';
import { suggestNext } from '../../src/home/next.js';
import type { LastScan, ProjectStatus, ServerStatus } from '../../src/home/status.js';

const SCAN: LastScan = { at: '2026-10-28T10:00:00.000Z', ageDays: 1, verdict: { tone: 'green', text: 'No issues found' }, open: [], urgent: 0, unverifiable: 0 };
const SERVER: ServerStatus = { name: 'web-1', address: '203.0.113.10', env: 'prod', collector: 'fresh' };
const RISK = { findingId: 'code-secrets-working-tree@code', owner: 'Priya', reason: 'rotating the key next sprint', expires: '2026-10-31', daysLeft: 3 };

function status(over: Partial<ProjectStatus> = {}): ProjectStatus {
  return { name: 'shop', stack: [], git: true, lastScan: SCAN, websites: [], servers: [], unscanned: [], accepted: [], pendingLessons: 0, checklistExported: true, ...over };
}

describe('suggestNext', () => {
  it('1. never scanned: run the first scan', () => {
    expect(suggestNext(status({ lastScan: undefined }))).toMatchObject({ action: 'scan', text: expect.stringContaining('not been scanned yet') });
  });

  it('2. a server without collector output, or with stale output: add it, naming the server', () => {
    expect(suggestNext(status({ servers: [{ ...SERVER, collector: 'none' }] }))).toMatchObject({ action: 'collector', host: 'web-1', text: expect.stringContaining('web-1 has no collector output yet') });
    expect(suggestNext(status({ servers: [{ ...SERVER, collector: 'stale' }] }))).toMatchObject({ action: 'collector', text: expect.stringContaining('older than 7 days') });
  });

  it('3. open critical or high issues: see what to fix first', () => {
    expect(suggestNext(status({ lastScan: { ...SCAN, urgent: 2 } }))).toMatchObject({ action: 'fixes', text: expect.stringContaining('2 high-priority issue(s)') });
  });

  it('4. an accepted risk ending within 7 days: look at accepted risks', () => {
    expect(suggestNext(status({ accepted: [RISK] }))).toMatchObject({ action: 'risks', text: expect.stringContaining('in 3 day(s)') });
    expect(suggestNext(status({ accepted: [{ ...RISK, daysLeft: 0 }] })).text).toContain('ends today');
    expect(suggestNext(status({ accepted: [{ ...RISK, daysLeft: 8 }] })).action).not.toBe('risks');
  });

  it('5. a site or server the last scan did not reach, or a scan over 7 days old: scan again', () => {
    expect(suggestNext(status({ unscanned: ['https://shop.example.com'] }))).toMatchObject({ action: 'scan', text: expect.stringContaining('https://shop.example.com has not been scanned yet') });
    expect(suggestNext(status({ lastScan: { ...SCAN, ageDays: 8 } }))).toMatchObject({ action: 'scan', text: expect.stringContaining('8 days old') });
  });

  it('6. the checklist was never exported: review what the scan cannot see', () => {
    expect(suggestNext(status({ checklistExported: false })).action).toBe('checklist');
  });

  it('7. otherwise: nothing pressing', () => {
    expect(suggestNext(status())).toMatchObject({ action: 'scan', text: expect.stringContaining('Nothing pressing') });
  });

  it('applies the rules in order: the first match wins', () => {
    expect(suggestNext(status({ servers: [{ ...SERVER, collector: 'none' }], lastScan: { ...SCAN, urgent: 1 } })).action).toBe('collector');
    expect(suggestNext(status({ lastScan: { ...SCAN, urgent: 1 }, accepted: [RISK] })).action).toBe('fixes');
    expect(suggestNext(status({ accepted: [RISK], lastScan: { ...SCAN, ageDays: 30 } })).action).toBe('risks');
    expect(suggestNext(status({ unscanned: ['web-1'], checklistExported: false })).action).toBe('scan');
  });
});
```

Create `test/home/status.test.ts`:

```ts
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { checklistFile, projectStatus } from '../../src/home/status.js';
import { SnapshotStore } from '../../src/host/store.js';
import { initProject } from '../../src/project/init.js';
import { scanNoAi } from '../../src/scan/no-ai.js';
import { FIXED_NOW } from '../helpers/ctx.js';
import { repoWith } from '../helpers/git.js';
import { FAKE } from '../helpers/secrets.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

const later = (days: number) => new Date(FIXED_NOW.getTime() + days * 86_400_000);
const FIXTURE = readFileSync(new URL('../fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8');

async function project(): Promise<string> {
  const dir = await tempDir();
  await repoWith(dir, { 'src/app.ts': `const id = '${FAKE.awsKeyId}';\n` });
  await initProject(dir, {
    name: 'shop',
    targets: [{ id: 'shop', url: 'https://shop.example.com', type: 'web', env: 'prod' }],
    hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }],
  });
  return dir;
}

describe('projectStatus', () => {
  it('a project never scanned: what is set up, and that nothing has run', async () => {
    const s = await projectStatus(await project(), FIXED_NOW);
    expect(s).toMatchObject({
      name: 'shop',
      git: true,
      websites: [{ id: 'shop', url: 'https://shop.example.com', env: 'prod' }],
      servers: [{ name: 'web-1', address: '203.0.113.10', env: 'prod', collector: 'none' }],
      unscanned: [],
      accepted: [],
      pendingLessons: 0,
      checklistExported: false,
    });
    expect(s.lastScan).toBeUndefined();
  });

  it('after a code-only scan: its age, verdict and open issues, and the site and server it did not reach', async () => {
    const dir = await project();
    await scanNoAi(dir, { only: ['code'], trigger: 'cli', now: () => FIXED_NOW });
    const s = await projectStatus(dir, later(10));
    expect(s.lastScan?.ageDays).toBe(10);
    expect(s.lastScan?.urgent).toBeGreaterThan(0);
    expect(s.lastScan?.verdict.text).toContain('Needs attention');
    expect(s.lastScan?.open.reduce((n, [, c]) => n + c, 0)).toBeGreaterThan(0);
    expect(s.unscanned).toEqual(['https://shop.example.com', 'web-1']);
  });

  it('collector output is fresh, then stale after 7 days', async () => {
    const dir = await project();
    await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', FIXTURE);
    expect((await projectStatus(dir, FIXED_NOW)).servers[0]?.collector).toBe('fresh');
    expect((await projectStatus(dir, later(8))).servers[0]?.collector).toBe('stale');
  });

  it('accepted risks in force, soonest first, with the days left; lapsed ones are left out', async () => {
    const dir = await project();
    await writeFiles(dir, {
      '.secagent/knowledge/exceptions.yaml': [
        'exceptions:',
        '  - { finding_id: b@code, owner: Priya, reason: rotating next sprint, expires: "2026-11-20" }',
        '  - { finding_id: a@code, owner: Sam, reason: vendor fix pending, expires: "2026-10-31" }',
        '  - { finding_id: c@code, owner: Sam, reason: an old decision, expires: "2026-10-01" }',
        '',
      ].join('\n'),
    });
    expect((await projectStatus(dir, FIXED_NOW)).accepted).toEqual([
      { findingId: 'a@code', owner: 'Sam', reason: 'vendor fix pending', expires: '2026-10-31', daysLeft: 3 },
      { findingId: 'b@code', owner: 'Priya', reason: 'rotating next sprint', expires: '2026-11-20', daysLeft: 23 },
    ]);
  });

  it('counts lessons waiting for review, and notices the exported checklist', async () => {
    const dir = await project();
    await writeFiles(dir, {
      '.secagent/knowledge/lessons/idea.md': '---\nid: idea\ntitle: A proposed lesson\nadded_by: learn-2026-10-28\nsource_url: https://owasp.org/x\nquote: some exact sentence from the page\nretrieved_at: "2026-10-28"\nreview: pending\n---\nBody of the lesson that explains what to do next time.\n',
      '.secagent/reports/checklist.md': '# checklist\n',
    });
    const s = await projectStatus(dir, FIXED_NOW);
    expect(s.pendingLessons).toBe(1);
    expect(s.checklistExported).toBe(true);
    expect(checklistFile(dir)).toBe(path.join(dir, '.secagent', 'reports', 'checklist.md'));
  });
});
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/home`
Expected: FAIL, the modules do not exist.

- [ ] **Step 3: Write `src/home/status.ts`**

```ts
import { access } from 'node:fs/promises';
import path from 'node:path';
import { repoState } from '../code/git.js';
import { FindingsStore } from '../findings/store.js';
import { snapshotFreshness, SnapshotStore } from '../host/store.js';
import { loadExceptions } from '../kb/exceptions.js';
import { pendingLessons } from '../kb/write.js';
import { projectStateDir } from '../paths.js';
import { loadProject } from '../project/schema.js';
import { verdict, type Tone } from '../report/model.js';
import { SEVERITIES, type Severity } from '../types.js';

const DAY_MS = 86_400_000;

export interface LastScan {
  at: string;
  /** Whole days since the scan. */
  ageDays: number;
  verdict: { tone: Tone; text: string };
  /** Open findings per severity, most severe first; severities with none are left out. */
  open: Array<[Severity, number]>;
  /** Open critical and high findings. */
  urgent: number;
  /** Findings that could not be checked. */
  unverifiable: number;
}

export interface ServerStatus {
  name: string;
  address: string;
  env: string;
  /** The stored collector output: none, fresh, or stale (older than 7 days). */
  collector: 'none' | 'fresh' | 'stale';
}

export interface AcceptedRisk {
  findingId: string;
  owner: string;
  reason: string;
  expires: string;
  /** Days until the last day it holds; 0 on that day. */
  daysLeft: number;
}

export interface ProjectStatus {
  name: string;
  stack: string[];
  git: boolean;
  lastScan?: LastScan;
  websites: Array<{ id: string; url: string; env: string }>;
  servers: ServerStatus[];
  /** Websites (by URL) and servers (by name) in project.yaml with no result in the last scan. */
  unscanned: string[];
  /** Accepted risks in force today, the soonest to end first. */
  accepted: AcceptedRisk[];
  pendingLessons: number;
  checklistExported: boolean;
}

/** Where the home screen writes the review checklist (reports/ is git-ignored). */
export function checklistFile(dir: string): string {
  return path.join(projectStateDir(dir), 'reports', 'checklist.md');
}

async function exists(file: string): Promise<boolean> {
  try {
    await access(file);
    return true;
  } catch {
    return false;
  }
}

/** Where the project stands, from local files only: no network, nothing written. */
export async function projectStatus(dir: string, now: Date): Promise<ProjectStatus> {
  const project = await loadProject(dir);
  const record = await new FindingsStore(dir).latest();
  const store = new SnapshotStore(dir, () => now);
  const servers: ServerStatus[] = [];
  for (const h of project.hosts) {
    // A host with only future-dated output throws; that output cannot be used, so it counts as none.
    const stored = await store.latest(h.name).catch(() => undefined);
    const collector = !stored ? 'none' : snapshotFreshness(stored.snapshot.collected_at, now).state === 'stale' ? 'stale' : 'fresh';
    servers.push({ name: h.name, address: h.address, env: h.env, collector });
  }

  let lastScan: LastScan | undefined;
  if (record) {
    const open = record.findings.filter((f) => f.status === 'open');
    lastScan = {
      at: record.scanned_at,
      ageDays: Math.max(0, Math.floor((now.getTime() - Date.parse(record.scanned_at)) / DAY_MS)),
      verdict: verdict(record),
      open: SEVERITIES.map((s) => [s, open.filter((f) => f.severity === s).length] as [Severity, number]).filter(([, n]) => n > 0),
      urgent: open.filter((f) => f.severity === 'critical' || f.severity === 'high').length,
      unverifiable: record.findings.filter((f) => f.status === 'unverifiable').length,
    };
  }
  const reached = new Set(record?.results.map((r) => r.target) ?? []);
  const unscanned = record
    ? [...project.targets.filter((t) => !reached.has(t.id)).map((t) => t.url), ...project.hosts.filter((h) => !reached.has(h.name)).map((h) => h.name)]
    : [];

  const today = now.toISOString().slice(0, 10);
  const accepted = (await loadExceptions(dir))
    .filter((x) => today <= x.expires)
    .map((x) => ({ findingId: x.finding_id, owner: x.owner, reason: x.reason, expires: x.expires, daysLeft: Math.round((Date.parse(x.expires) - Date.parse(today)) / DAY_MS) }))
    .sort((a, b) => a.expires.localeCompare(b.expires) || a.findingId.localeCompare(b.findingId));

  return {
    name: project.name,
    stack: Object.values(project.stack).filter((v): v is string => typeof v === 'string'),
    git: (await repoState(dir)).state === 'repo',
    ...(lastScan ? { lastScan } : {}),
    websites: project.targets.map((t) => ({ id: t.id, url: t.url, env: t.env })),
    servers,
    unscanned,
    accepted,
    pendingLessons: (await pendingLessons(dir).catch(() => [])).length,
    checklistExported: await exists(checklistFile(dir)),
  };
}
```

- [ ] **Step 4: Write `src/home/next.ts`**

```ts
import type { ProjectStatus } from './status.js';

export type HomeAction = 'fixes' | 'scan' | 'report' | 'checklist' | 'collector' | 'risks' | 'verify' | 'lessons' | 'ai' | 'settings' | 'help' | 'exit';

export interface Suggestion {
  action: HomeAction;
  /** What I noticed and why it is the next step, in a sentence or two. */
  text: string;
  /** The server a collector suggestion is about. */
  host?: string;
}

const OLD_SCAN_DAYS = 7;
const ENDING_SOON_DAYS = 7;

/** The next step, by fixed rules in order (spec §4.2): the same status always gives the same suggestion. */
export function suggestNext(s: ProjectStatus): Suggestion {
  const scan = s.lastScan;
  if (!scan) return { action: 'scan', text: 'This project has not been scanned yet. Let me run the first scan.' };
  const server = s.servers.find((h) => h.collector !== 'fresh');
  if (server) {
    const state = server.collector === 'none' ? 'has no collector output yet' : 'has collector output older than 7 days';
    return { action: 'collector', host: server.name, text: `${server.name} ${state}, so I cannot check its SSH, nginx or packages. Add it next.` };
  }
  if (scan.urgent > 0) return { action: 'fixes', text: `${scan.urgent} high-priority issue(s) are open. Fix those first; I will show you what to change.` };
  const ending = s.accepted.find((a) => a.daysLeft <= ENDING_SOON_DAYS);
  if (ending) {
    const when = ending.daysLeft === 0 ? 'today' : `in ${ending.daysLeft} day(s)`;
    return { action: 'risks', text: `The accepted risk on ${ending.findingId} ends ${when}; after that it counts as open again.` };
  }
  if (s.unscanned.length > 0) {
    const one = s.unscanned.length === 1;
    return { action: 'scan', text: `${s.unscanned.join(', ')} ${one ? 'has' : 'have'} not been scanned yet. Scan again to include ${one ? 'it' : 'them'}.` };
  }
  if (scan.ageDays > OLD_SCAN_DAYS) return { action: 'scan', text: `The last scan is ${scan.ageDays} days old. Scan again to see where things stand now.` };
  if (!s.checklistExported) {
    return { action: 'checklist', text: 'The scan cannot see everything: routes without a login check, unsafe queries, cloud settings. The review checklist covers those.' };
  }
  return { action: 'scan', text: 'Nothing pressing. Scan again after your next deploy.' };
}
```

- [ ] **Step 5: Run the tests to verify they pass**

Run: `npx vitest run test/home`
Expected: PASS (status 5 tests, next 8 tests).

- [ ] **Step 6: Typecheck, full tests, commit**

```bash
npm run typecheck && npm test
git add src/home test/home
git commit -m "feat(home): project status from local files and the suggested next step"
```

---

### Task 4: Wizard plumbing the home screen needs

Moves the wizard helpers unchanged into `src/wizard/steps.ts` (so `src/home/` can use them without importing `run.ts`), adds `askDepsFor`, the `start` option on `askPlan`, exports `askSnapshot`, and makes the scan's opening line speak in the agent's voice. The wizard still behaves as before; its tests pass unchanged.

**Files:**
- Create: `src/wizard/steps.ts`
- Modify: `src/wizard/run.ts`
- Modify: `src/wizard/questions.ts`
- Test: `test/wizard/questions.test.ts`, `test/wizard/run.test.ts`

**Interfaces:**
- Consumes: existing wizard code.
- Produces (all in `src/wizard/steps.ts` unless noted):
  - `interface WizardDeps` (unchanged, moved), `openWithSystem(file): Promise<boolean>`, `exists(file): Promise<boolean>`
  - `scanWithProgress(dir, plan, deps): Promise<ScanRecord>`, `showResult(record, input, deps): void`, `savePlan(dir, plan, now): Promise<void>`, `writeCollectorFile(dir, host): Promise<string>`
  - `acceptFromMenu(dir, input, open, deps, now): Promise<boolean>`, `reviewLessons(dir, deps, now): Promise<void>`
  - `askDepsFor(dir: string, now: () => Date, extra?: { existing?: ProjectConfig; start?: AskDeps['start']; detection?: StackDetection }): Promise<AskDeps>`
  - In `src/wizard/questions.ts`: `AskDeps.start?: 'again' | 'change' | 'fresh'`; `askSnapshot(p: Prompter, deps: Pick<AskDeps, 'dir' | 'now' | 'readFile'>, host: string): Promise<string | undefined>`; `collectorSteps(file: string, host: string): string`

- [ ] **Step 1: Write the failing tests**

In `test/wizard/questions.test.ts`, change the import to:

```ts
import { askPlan, collectorSteps, targetIdFor, type AskDeps } from '../../src/wizard/questions.js';
```

and add inside `describe('an existing project', ...)`:

```ts
    it('start: again goes straight to consent, without the "already set up" question', async () => {
      const p = new ScriptedPrompter([true]);
      const plan = await askPlan(p, deps({ existing: existing(), start: 'again' }));
      p.done();
      expect(p.asked).toEqual(['I own these systems or have written permission to test them']);
      expect(plan?.config).toEqual(existing());
    });

    it('start: change and fresh skip the question too', async () => {
      const change = new ScriptedPrompter([undefined, undefined, true, false, undefined, true, false, true]);
      expect((await askPlan(change, deps({ existing: existing(), start: 'change' })))?.config.targets).toEqual(existing().targets);
      change.done();
      expect(change.asked[0]).toBe('Project name');
      const fresh = new ScriptedPrompter(['newname', ['code']]);
      expect((await askPlan(fresh, deps({ existing: existing(), start: 'fresh' })))?.config).toMatchObject({ name: 'newname', targets: [], hosts: [] });
      fresh.done();
    });
```

and at the end of the file, a new top-level block:

```ts
describe('collectorSteps', () => {
  it('says how to run the collector on the server and what to bring back', () => {
    expect(collectorSteps('/work/shop/.secagent/hosts/web-1/collector.sh', 'web-1')).toBe(
      'Copy /work/shop/.secagent/hosts/web-1/collector.sh to web-1, read it, then run it there:\n  sudo sh collector.sh > web-1.json\nand bring web-1.json back.',
    );
  });
});
```

In `test/wizard/run.test.ts`, in the first test (`code only: saves the settings...`), add after `expect(out).toContain('Code');`:

```ts
    expect(out).toContain("I'm running 5 checks on your code.");
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/wizard`
Expected: FAIL: `collectorSteps` is not exported, `start` is ignored (the scripted `true` answers the "already set up" select), and the narration line is missing.

- [ ] **Step 3: Change `src/wizard/questions.ts`**

3a. In `interface AskDeps`, add after `existing?: ProjectConfig;`:

```ts
  /** For a project that is already set up: scan again with its settings, change them, or start over. Without it, I ask. */
  start?: 'again' | 'change' | 'fresh';
```

3b. In `askPlan`, replace

```ts
    const action = await p.select({
      message: 'This project is already set up. What now?',
```

with

```ts
    const action = deps.start ?? await p.select({
      message: 'This project is already set up. What now?',
```

(the select and the rest of the block stay as they are; Task 6 removes the select).

3c. Add above `askSnapshot`:

```ts
/** How to run the collector on a server and what to bring back. */
export function collectorSteps(file: string, host: string): string {
  return `Copy ${file} to ${host}, read it, then run it there:\n  sudo sh ${path.basename(file)} > ${host}.json\nand bring ${host}.json back.`;
}
```

3d. Change the `askSnapshot` signature to export it and take only what it uses:

```ts
export async function askSnapshot(p: Prompter, deps: Pick<AskDeps, 'dir' | 'now' | 'readFile'>, host: string): Promise<string | undefined> {
```

3e. In `askServers`, replace the `p.note(\`Copy ${file} to ${name}, ...\`)` call with:

```ts
      p.note(collectorSteps(file, name));
```

- [ ] **Step 4: Create `src/wizard/steps.ts` by moving code out of `src/wizard/run.ts`**

Move these from `src/wizard/run.ts` to the new `src/wizard/steps.ts`, unchanged except where noted: `interface WizardDeps`, `openWithSystem`, `exists` (now `export`), `symbolFor`, `toneOf`, `scanWithProgress` (now `export`, plus the opening line below), `showResult` (now `export`), `savePlan` (now `export`), `writeCollectorFile` (now `export`), `acceptFromMenu` (now `export`), `reviewLessons` (now `export`). Then add `scopeOf` and `askDepsFor`. The new file:

```ts
import { spawn } from 'node:child_process';
import { access, mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import type { Advisories } from '../advisories/types.js';
import type { ScanRecord } from '../findings/schema.js';
import { makeCollector } from '../host/collector.js';
import { SnapshotStore } from '../host/store.js';
import { acceptRisk } from '../kb/accept.js';
import { KbError } from '../kb/lesson.js';
import { approveLesson, pendingLessons, rejectLesson } from '../kb/write.js';
import type { NetClient } from '../net/scoped.js';
import { recordConsent } from '../project/consent.js';
import { initProject } from '../project/init.js';
import { saveProject, type ProjectConfig } from '../project/schema.js';
import { detectStack, type StackDetection } from '../project/stack.js';
import { AREA_LABEL, topFixes, verdict, whereOf, type Area, type ReportInput } from '../report/model.js';
import { scanNoAi } from '../scan/no-ai.js';
import type { Prompter } from '../ui/prompt.js';
import { SYMBOL, type Style } from '../ui/style.js';
import { SEVERITIES, type CheckResult } from '../types.js';
import type { AskDeps, WizardPlan } from './questions.js';

// ... WizardDeps, openWithSystem, exists, symbolFor, toneOf: moved unchanged (exists gains `export`) ...

/** "your code, 2 website(s) and 1 server(s)": what this scan covers, in words. */
function scopeOf(plan: WizardPlan): string {
  const parts = [
    ...(plan.groups.includes('code') ? ['your code'] : []),
    ...(plan.groups.includes('web') ? [`${plan.config.targets.length} website(s)`] : []),
    ...(plan.groups.includes('host') ? [`${plan.config.hosts.length} server(s)`] : []),
  ];
  return parts.length > 1 ? `${parts.slice(0, -1).join(', ')} and ${parts.at(-1)}` : (parts[0] ?? 'nothing');
}

// ... scanWithProgress: moved, with `export`, and its onPlan line changed to:
//     onPlan: (n) => {
//       total = n;
//       out.write(`\n${style.bold(`I'm running ${n} checks on ${scopeOf(plan)}.`)}\n`);
//     },

// ... showResult, savePlan, writeCollectorFile, acceptFromMenu, reviewLessons: moved unchanged, with `export` ...

/** What the setup questions need: the folder, its stack, file reading and the collector writer. */
export async function askDepsFor(
  dir: string,
  now: () => Date,
  extra: { existing?: ProjectConfig; start?: AskDeps['start']; detection?: StackDetection } = {},
): Promise<AskDeps> {
  return {
    dir,
    ...(extra.existing ? { existing: extra.existing } : {}),
    ...(extra.start ? { start: extra.start } : {}),
    detection: extra.detection ?? (await detectStack(dir)),
    now,
    readFile: (file) => readFile(file, 'utf8'),
    writeCollector: (host) => writeCollectorFile(dir, host),
  };
}
```

(The `// ...` lines stand for the functions moved verbatim from `run.ts`; copy them in full. Do not retype them.)

- [ ] **Step 5: Slim `src/wizard/run.ts`**

Replace its imports with:

```ts
import { CatalogError } from '../checks/catalog.js';
import { ObservationError } from '../checks/errors.js';
import { repoState } from '../code/git.js';
import { KbError } from '../kb/lesson.js';
import { pendingLessons } from '../kb/write.js';
import { loadProject, ProjectConfigError, projectFile, type ProjectConfig } from '../project/schema.js';
import { ScopeError } from '../project/scope.js';
import { detectStack } from '../project/stack.js';
import { loadReportInput } from '../report/model.js';
import { writeReport } from '../report/write.js';
import { PromptCancelled } from '../ui/prompt.js';
import { askPlan } from './questions.js';
import { acceptFromMenu, askDepsFor, exists, openWithSystem, reviewLessons, savePlan, scanWithProgress, showResult, type WizardDeps } from './steps.js';

export type { WizardDeps } from './steps.js';
```

Keep only `runWizard` in the file. In `runWizard`, replace the `askPlan` call with:

```ts
    const plan = await askPlan(prompter, await askDepsFor(dir, now, { detection, ...(existing ? { existing } : {}) }));
```

- [ ] **Step 6: Run the tests to verify they pass**

Run: `npx vitest run test/wizard test/cli.test.ts test/demo.test.ts`
Expected: PASS. Every existing wizard test passes unchanged; the new ones pass.

- [ ] **Step 7: Typecheck, full tests, commit**

```bash
npm run typecheck && npm test
git add src/wizard test/wizard
git commit -m "refactor(wizard): move the scan steps to steps.ts; askPlan start option; scan opens in the agent's voice"
```

---

### Task 5: The home screen's actions

**Files:**
- Create: `src/home/actions.ts`
- Modify: `src/report/model.ts` (export `fixText`)
- Modify: `src/wizard/steps.ts` (add `fetchImpl` to `WizardDeps`)
- Test: `test/home/actions.test.ts`

**Interfaces:**
- Consumes: Task 1 `GUIDES`, `renderGuide`; Task 2 `formatClaim`, `mcpSetupLines`, `formatDoctor`; Task 3 `projectStatus`, `checklistFile`; Task 4 `WizardDeps`, `acceptFromMenu`, `writeCollectorFile`, `openWithSystem`, `exists`, `askSnapshot`, `collectorSteps`.
- Produces (in `src/home/actions.ts`; all take `(dir, deps: WizardDeps)` unless noted):
  - `showFixes(dir, deps): Promise<void>`, `findingDetail(input: ReportInput, f: Finding, style: Style): string`
  - `openReport(dir, deps): Promise<void>`
  - `suggestedAreas(dir: string, project: ProjectConfig): Promise<string[]>`, `exportChecklist(dir, deps): Promise<void>`
  - `addCollectorOutput(dir, deps, suggested?: string): Promise<void>`
  - `checkCveClaim(dir, deps): Promise<void>`
  - `acceptedRisks(dir, deps): Promise<boolean>`: true when a risk was accepted (the caller scans again)
  - `connectAi(dir, deps): void`, `checkSetup(dir, deps): Promise<void>`, `showGuides(deps): Promise<void>`
  - `WizardDeps.fetchImpl?: typeof fetch`

- [ ] **Step 1: Write the failing test**

Create `test/home/actions.test.ts`:

```ts
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { PassThrough } from 'node:stream';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { main } from '../../src/cli.js';
import {
  acceptedRisks,
  addCollectorOutput,
  checkCveClaim,
  checkSetup,
  connectAi,
  exportChecklist,
  openReport,
  showFixes,
  showGuides,
  suggestedAreas,
} from '../../src/home/actions.js';
import { checklistFile } from '../../src/home/status.js';
import { SnapshotStore } from '../../src/host/store.js';
import { initProject } from '../../src/project/init.js';
import { loadProject } from '../../src/project/schema.js';
import { scanNoAi } from '../../src/scan/no-ai.js';
import { createStyle } from '../../src/ui/style.js';
import type { WizardDeps } from '../../src/wizard/steps.js';
import { fixtureAdvisories } from '../helpers/advisories.js';
import { FIXED_NOW } from '../helpers/ctx.js';
import { repoWith } from '../helpers/git.js';
import { ScriptedPrompter } from '../helpers/prompter.js';
import { FAKE } from '../helpers/secrets.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

afterEach(() => {
  vi.restoreAllMocks();
});

const FIXTURE = readFileSync(new URL('../fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8');
const ID = 'code-secrets-working-tree@code';

function setup(answers: unknown[], extra: Partial<WizardDeps> = {}) {
  const out = new PassThrough();
  let printed = '';
  out.on('data', (c: Buffer) => {
    printed += c.toString();
  });
  const prompter = new ScriptedPrompter(answers);
  const deps: WizardDeps = { prompter, out, style: createStyle({ isTTY: false }), now: () => FIXED_NOW, openFile: async () => true, ...extra };
  return { prompter, deps, text: () => printed };
}

/** A repo with a leaked key, set up, scanned (code) at FIXED_NOW. */
async function scanned(opts: Parameters<typeof initProject>[1] = {}): Promise<string> {
  const dir = await tempDir();
  await repoWith(dir, { 'src/app.ts': `// config\nconst id = '${FAKE.awsKeyId}';\n` });
  await initProject(dir, opts);
  await scanNoAi(dir, { only: ['code'], trigger: 'cli', now: () => FIXED_NOW });
  return dir;
}

async function withServer(): Promise<string> {
  const dir = await tempDir();
  await initProject(dir, { hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }] });
  return dir;
}

describe('home actions', () => {
  it('fix first: explains a finding (where, what, why, fix, evidence) and never shows the secret', async () => {
    const dir = await scanned();
    const { prompter, deps, text } = setup([ID, '']);
    await showFixes(dir, deps);
    prompter.done();
    const out = text();
    expect(out).toContain('Failed: No secrets in the project');
    expect(out).toContain("Where     this project's code");
    expect(out).toContain('Why       ');
    expect(out).toContain('Fix       ');
    expect(out).toMatch(/Evidence  ev_/);
    expect(out).not.toContain(FAKE.awsKeyId);
  });

  it('open the report: opens the chosen one and says where the Markdown is', async () => {
    const dir = await scanned();
    const openFile = vi.fn(async () => true);
    const { deps, text } = setup(['html'], { openFile });
    await openReport(dir, deps);
    expect(openFile).toHaveBeenCalledWith(path.join(dir, '.secagent', 'reports', 'latest.html'));
    expect(text()).toContain(path.join(dir, '.secagent', 'reports', 'latest.md'));
  });

  it('checklist areas follow the project: always secrets; websites add surface, auth, input; servers or CI add infra', async () => {
    const plain = await tempDir();
    await initProject(plain);
    expect(await suggestedAreas(plain, await loadProject(plain))).toEqual(['secrets']);
    const ci = await tempDir();
    await writeFiles(ci, { '.github/workflows/ci.yml': 'on: push\n' });
    await initProject(ci, { targets: [{ id: 'shop', url: 'https://shop.example.com', type: 'web', env: 'prod' }] });
    expect(await suggestedAreas(ci, await loadProject(ci))).toEqual(['surface', 'auth', 'input', 'secrets', 'infra']);
  });

  it('checklist hand-off writes the same file as secagent checklist for those areas, and says how to work through it', async () => {
    const dir = await scanned({ targets: [{ id: 'shop', url: 'https://shop.example.com', type: 'web', env: 'prod' }] });
    const { prompter, deps, text } = setup([undefined]);
    await exportChecklist(dir, deps);
    prompter.done();
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const viaCli = path.join(dir, 'cli-checklist.md');
    expect(await main(['checklist', '--dir', dir, '--area', 'surface', '--area', 'auth', '--area', 'input', '--area', 'secrets', '--out', viaCli])).toBe(0);
    expect(readFileSync(checklistFile(dir), 'utf8')).toBe(readFileSync(viaCli, 'utf8'));
    expect(text()).toContain('/security-review');
    expect(text()).toContain('a review, not scan results');
  });

  it('collector output: writes the script on request with the steps, then stores valid output like snapshot add', async () => {
    const dir = await withServer();
    await writeFiles(dir, { 'web-1.json': FIXTURE });
    const first = setup([undefined, true, '']);
    await addCollectorOutput(dir, first.deps);
    expect(first.prompter.notes.join('\n')).toContain('sudo sh collector.sh > web-1.json');
    expect(existsSync(path.join(dir, '.secagent', 'hosts', 'web-1', 'collector.sh'))).toBe(true);
    expect(first.text()).toContain('Nothing stored');
    const second = setup([undefined, false, 'web-1.json']);
    await addCollectorOutput(dir, second.deps, 'web-1');
    second.prompter.done();
    expect(second.text()).toContain("Stored web-1's collector output");
    expect((await new SnapshotStore(dir, () => FIXED_NOW).latest('web-1'))?.snapshot.os.codename).toBe('noble');
  });

  it("CVE claim: the same verdict as secagent verify; re-asks a malformed id", async () => {
    const dir = await withServer();
    await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', FIXTURE);
    const { prompter, deps, text } = setup([undefined, 'not-a-cve', 'CVE-2024-6387', ''], { advisories: fixtureAdvisories(await tempDir()) });
    await checkCveClaim(dir, deps);
    prompter.done();
    expect(prompter.rejected).toHaveLength(1);
    expect(text()).toContain('CVE-2024-6387 on web-1: fixed_in_installed');
  });

  it('accepted risks: none yet, then accepting one returns true and lists it the next time', async () => {
    const dir = await scanned();
    const first = setup(['accept', ID, 'Priya', 'rotating the key next sprint', '2026-12-15']);
    expect(await acceptedRisks(dir, first.deps)).toBe(true);
    first.prompter.done();
    expect(first.text()).toContain('No accepted risks right now.');
    const second = setup(['back']);
    expect(await acceptedRisks(dir, second.deps)).toBe(false);
    expect(second.text()).toContain(`${ID}  Priya: "rotating the key next sprint"  until 2026-12-15 (48 day(s) left)`);
  });

  it('connect an AI assistant prints the mcp setup command and what to ask', async () => {
    const dir = await withServer();
    const { deps, text } = setup([]);
    connectAi(dir, deps);
    expect(text()).toContain('claude mcp add secagent --');
    expect(text()).toContain('/security-review');
  });

  it('check this machine prints what secagent doctor prints', async () => {
    const dir = await withServer();
    const { deps, text } = setup([], { fetchImpl: (async () => new Response('{}', { status: 200 })) as typeof fetch });
    await checkSetup(dir, deps);
    expect(text()).toContain('✓ Node');
    expect(text()).toContain('No collector snapshot for server web-1');
  });

  it('guides: prints the chosen one until Back', async () => {
    const { prompter, deps, text } = setup(['servers', 'safety', '']);
    await showGuides(deps);
    prompter.done();
    expect(text()).toContain('Checking a server');
    expect(text()).toContain('What secagent touches');
  });
});
```

(48 days: 2026-10-28 to 2026-12-15 is 4 + 30 + 14 = 48.)

- [ ] **Step 2: Run the test to verify it fails**

Run: `npx vitest run test/home/actions.test.ts`
Expected: FAIL, `Cannot find module '../../src/home/actions.js'`.

- [ ] **Step 3: Small additions to existing files**

In `src/report/model.ts`, change `function fixText(f: Finding): string | undefined {` to `export function fixText(f: Finding): string | undefined {`.

In `src/wizard/steps.ts`, add to `interface WizardDeps`:

```ts
  /** The setup check's request to the advisory database (tests); defaults to fetch. */
  fetchImpl?: typeof fetch;
```

- [ ] **Step 4: Write `src/home/actions.ts`**

```ts
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { createAdvisories } from '../advisories/index.js';
import { loadCheckInstances } from '../checks/catalog.js';
import { CHECK_TYPES } from '../checks/registry.js';
import { doctor, formatDoctor } from '../doctor.js';
import { EvidenceStore } from '../evidence/store.js';
import type { Finding } from '../findings/schema.js';
import { FindingsStore } from '../findings/store.js';
import { renderGuide } from '../help/render.js';
import { GUIDES } from '../help/topics.js';
import { SnapshotStore } from '../host/store.js';
import { loadShippedChecklists, renderChecklist, selectAreas } from '../kb/checklist.js';
import { mcpSetupLines } from '../mcp/setup.js';
import { GLOBAL_CHECKS_DIR, projectStateDir } from '../paths.js';
import { loadProject, type ProjectConfig } from '../project/schema.js';
import { Scope } from '../project/scope.js';
import { fixText, loadReportInput, whereOf, type ReportInput } from '../report/model.js';
import { SEVERITY_RANK } from '../types.js';
import type { Prompter } from '../ui/prompt.js';
import type { Style } from '../ui/style.js';
import { verifyClaim } from '../verify/claim.js';
import { formatClaim } from '../verify/format.js';
import { askSnapshot, collectorSteps } from '../wizard/questions.js';
import { acceptFromMenu, exists, openWithSystem, writeCollectorFile, type WizardDeps } from '../wizard/steps.js';
import { checklistFile, projectStatus } from './status.js';

const CVE_ID = /^CVE-\d{4}-\d{4,}$/i;
const INDENT = '\n            ';

function nowOf(deps: WizardDeps): () => Date {
  return deps.now ?? (() => new Date());
}

/** One finding in plain words, from the same fields the report uses. */
export function findingDetail(input: ReportInput, f: Finding, style: Style): string {
  const observed = input.record.results.find((r) => r.check_id === f.check_id && r.target === f.target)?.observed;
  const why = input.instances.get(f.check_id)?.why?.trim();
  const fix = fixText(f);
  const sideEffects = f.fix?.side_effects ?? [];
  return [
    `${style.bold(`Failed: ${f.title}`)}  ${style.dim(f.severity)}`,
    `  Where     ${whereOf(input.project, f.target)}`,
    ...(observed ? [`  Found     ${observed}`] : []),
    ...(why ? [`  Why       ${why.split('\n').join(INDENT)}`] : []),
    ...(fix ? [`  Fix       ${fix.split('\n').join(INDENT)}`] : []),
    ...(sideEffects.length > 0 ? [`  Watch out ${sideEffects.join(INDENT)}`] : []),
    `  Evidence  ${f.evidence.join(', ')}`,
  ].join('\n');
}

/** The open findings, most urgent first; pick one to see what to change. */
export async function showFixes(dir: string, deps: WizardDeps): Promise<void> {
  const { prompter, out, style } = deps;
  const input = await loadReportInput(dir);
  const open = (input?.record.findings ?? [])
    .filter((f) => f.status === 'open')
    .sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity] || a.id.localeCompare(b.id));
  if (!input || open.length === 0) {
    out.write('\nNothing is open, so there is nothing to fix right now.\n');
    return;
  }
  out.write(`\n${style.bold(`I found ${open.length} thing(s) to fix. Most urgent first:`)}\n`);
  for (;;) {
    const id = await prompter.select({
      message: 'Which one should I explain?',
      choices: [...open.map((f) => ({ value: f.id, label: `${f.severity.toUpperCase()}: ${f.title}`, hint: whereOf(input.project, f.target) })), { value: '', label: 'Back' }],
      default: open[0]?.id ?? '',
    });
    const f = open.find((x) => x.id === id);
    if (!f) return;
    out.write(`\n${findingDetail(input, f, style)}\n\n`);
  }
}

export async function openReport(dir: string, deps: WizardDeps): Promise<void> {
  const { prompter, out } = deps;
  const reports = path.join(projectStateDir(dir), 'reports');
  const which = await prompter.select({
    message: 'Which report?',
    choices: [
      { value: 'pdf' as const, label: 'PDF' },
      { value: 'html' as const, label: 'HTML', hint: 'opens in your browser' },
      { value: 'back' as const, label: 'Back' },
    ],
    default: 'pdf' as const,
  });
  if (which === 'back') return;
  const file = path.join(reports, `latest.${which}`);
  if (!(await (deps.openFile ?? openWithSystem)(file))) out.write(`Could not open it from here: ${file}\n`);
  out.write(`The Markdown version is ${path.join(reports, 'latest.md')}\n`);
}

/** Checklist areas that fit the project: websites → surface, auth, input; always secrets; servers or CI files → infra. */
export async function suggestedAreas(dir: string, project: ProjectConfig): Promise<string[]> {
  const ci = (await exists(path.join(dir, '.github', 'workflows'))) || (await exists(path.join(dir, '.gitlab-ci.yml')));
  return [...(project.targets.length > 0 ? ['surface', 'auth', 'input'] : []), 'secrets', ...(project.hosts.length > 0 || ci ? ['infra'] : [])];
}

/** Writes the review checklist for the chosen areas (same text as `secagent checklist`) and says how to work through it. */
export async function exportChecklist(dir: string, deps: WizardDeps): Promise<void> {
  const { prompter, out } = deps;
  const lists = await loadShippedChecklists(await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES));
  const areas = await prompter.multiselect({
    message: 'Which areas fit this project? (I ticked the ones that look relevant)',
    choices: lists.map((l) => ({ value: l.area, label: l.title, hint: `${l.items.length} checks` })),
    initial: await suggestedAreas(dir, await loadProject(dir)),
    min: 1,
  });
  const chosen = selectAreas(lists, areas);
  const file = checklistFile(dir);
  await mkdir(path.dirname(file), { recursive: true });
  await writeFile(file, renderChecklist(chosen, await new FindingsStore(dir).latest()), 'utf8');
  const shown = path.relative(dir, file);
  out.write(
    [
      '',
      `I wrote ${chosen.reduce((n, l) => n + l.items.length, 0)} checks to ${shown}: things only someone reading the code can decide.`,
      '',
      'Work through them with:',
      '  • Claude Code:  /security-review',
      `  • Another AI:   "Work through ${shown} against this code. For each item say pass, fail or unknown,`,
      '                   cite file:line, and list the fails first."',
      '  • By hand:      open the file',
      "Those answers are a review, not scan results; the scan's findings do not change.",
      '',
    ].join('\n'),
  );
}

function pickServer(prompter: Prompter, project: ProjectConfig, message: string, suggested?: string): Promise<string> {
  return prompter.select({
    message,
    choices: project.hosts.map((h) => ({ value: h.name, label: h.name, hint: `${h.address} · ${h.env}` })),
    default: suggested ?? project.hosts[0]?.name ?? '',
  });
}

/** Writes the collector on request, then checks and stores its output: the same store `secagent snapshot add` uses. */
export async function addCollectorOutput(dir: string, deps: WizardDeps, suggested?: string): Promise<void> {
  const { prompter, out } = deps;
  const now = nowOf(deps);
  const host = await pickServer(prompter, await loadProject(dir), 'Which server?', suggested);
  if (await prompter.confirm({ message: `Write the read-only collector for ${host} so you can run it on the server?`, default: true })) {
    prompter.note(collectorSteps(await writeCollectorFile(dir, host), host));
  }
  const text = await askSnapshot(prompter, { dir, now, readFile: (file) => readFile(file, 'utf8') }, host);
  if (!text) {
    out.write(`Nothing stored. ${host} stays "not checked" until you add its collector output.\n`);
    return;
  }
  const { snapshot } = await new SnapshotStore(dir, now).add(host, text);
  out.write(`Stored ${host}'s collector output (${snapshot.os.pretty_name || snapshot.os.id}, ${snapshot.packages.length} packages). Scan again so I can check it.\n`);
}

/** A scanner's CVE claim against a server's installed packages: the same call and output as `secagent verify`. */
export async function checkCveClaim(dir: string, deps: WizardDeps): Promise<void> {
  const { prompter, out } = deps;
  const project = await loadProject(dir);
  const name = await pickServer(prompter, project, 'Which server did the scanner report?');
  const cve = (await prompter.text({ message: 'Which CVE? (e.g. CVE-2024-6387)', validate: (v) => (CVE_ID.test(v.trim()) ? undefined : 'Enter an id like CVE-2024-6387') })).trim();
  const pkg = (await prompter.text({ message: 'The package the scanner named (Enter to skip)', default: '' })).trim();
  out.write(`\nLooking up ${cve} in the distro's advisories for ${name}'s installed packages (only package names and versions are sent)...\n`);
  const result = await verifyClaim(
    {
      host: new Scope(project).host(name),
      snapshots: new SnapshotStore(dir, deps.now),
      advisories: deps.advisories ?? createAdvisories(deps.now ? { now: deps.now } : {}),
      evidence: new EvidenceStore(dir, project.network.scan_label, deps.now),
      ...(deps.now ? { now: deps.now } : {}),
    },
    { cve, ...(pkg ? { package: pkg } : {}) },
  );
  out.write(`${formatClaim(result).join('\n')}\n`);
}

/** Lists the accepted risks; true when the person accepted a new one (the caller scans again, as before). */
export async function acceptedRisks(dir: string, deps: WizardDeps): Promise<boolean> {
  const { prompter, out, style } = deps;
  const now = nowOf(deps);
  const { accepted } = await projectStatus(dir, now());
  if (accepted.length === 0) out.write('\nNo accepted risks right now.\n');
  else {
    out.write(`\n${style.bold('Accepted risks')}\n`);
    for (const a of accepted) out.write(`  ${a.findingId}  ${a.owner}: "${a.reason}"  until ${a.expires} (${a.daysLeft === 0 ? 'last day' : `${a.daysLeft} day(s) left`})\n`);
    out.write('  After its date, each counts as open again.\n');
  }
  const input = await loadReportInput(dir);
  const open = input?.record.findings.filter((f) => f.status === 'open') ?? [];
  if (!input || open.length === 0) return false;
  const next = await prompter.select({
    message: 'Accept the risk of a finding?',
    choices: [
      { value: 'accept' as const, label: 'Accept the risk of a finding', hint: `${open.length} open` },
      { value: 'back' as const, label: 'Back' },
    ],
    default: 'back' as const,
  });
  return next === 'accept' && (await acceptFromMenu(dir, input, open, deps, now));
}

export function connectAi(dir: string, deps: WizardDeps): void {
  deps.out.write(`\n${mcpSetupLines(dir).join('\n')}\nIn Claude Code with the secagent plugin you can also type /security-review.\n`);
}

/** What `secagent doctor` checks and prints. */
export async function checkSetup(dir: string, deps: WizardDeps): Promise<void> {
  const { lines } = formatDoctor(await doctor(dir, { now: nowOf(deps), ...(deps.fetchImpl ? { fetchImpl: deps.fetchImpl } : {}) }));
  deps.out.write(`\n${lines.join('\n')}\n`);
}

export async function showGuides(deps: WizardDeps): Promise<void> {
  const { prompter, out } = deps;
  for (;;) {
    const name = await prompter.select({
      message: 'Which guide?',
      choices: [...GUIDES.map((g) => ({ value: g.name, label: g.title })), { value: '', label: 'Back' }],
      default: GUIDES[0]?.name ?? '',
    });
    const guide = GUIDES.find((g) => g.name === name);
    if (!guide) return;
    out.write(`\n${renderGuide(guide)}\n\n`);
  }
}
```

- [ ] **Step 5: Run the test to verify it passes**

Run: `npx vitest run test/home/actions.test.ts`
Expected: PASS (10 tests). If the "fix first" title differs, read `knowledge/checks/code-secrets*.yaml` for the exact `title` and adjust the expectation (the code is right; the expected text is a guess at the title).

- [ ] **Step 6: Typecheck, full tests, commit**

```bash
npm run typecheck && npm test
git add src/home/actions.ts src/report/model.ts src/wizard/steps.ts test/home/actions.test.ts
git commit -m "feat(home): fix-first detail, checklist hand-off, collector output, CVE claim, accepted risks, guides"
```

---

### Task 6: The home loop, and the first run's intro

**Files:**
- Create: `src/home/run.ts`
- Modify: `src/wizard/run.ts` (rewrite), `src/wizard/steps.ts` (add `scanAndReport`), `src/wizard/questions.ts` (drop the "already set up" select)
- Test: `test/home/run.test.ts` (new); update `test/wizard/run.test.ts`, `test/wizard/questions.test.ts`, `test/cli.test.ts`, `test/demo.test.ts`

**Interfaces:**
- Consumes: Tasks 3–5.
- Produces:
  - `runHome(dir: string, deps: WizardDeps, session: HomeSession): Promise<number>`, `interface HomeSession { plan?: WizardPlan }`
  - `renderStatus(s: ProjectStatus, next: Suggestion, style: Style): string`, `menuFor(s: ProjectStatus, next: Suggestion): Array<Choice<HomeAction>>`
  - `scanAndReport(dir: string, plan: WizardPlan, deps: WizardDeps): Promise<void>` in `src/wizard/steps.ts`
  - Home menu values (what tests answer): `fixes`, `scan`, `report`, `checklist`, `collector`, `risks`, `verify`, `lessons`, `ai`, `settings`, `help`, `exit`. Intro values: `setup`, `guides`, `quit`. Settings values: `change`, `fresh`, `doctor`, `back`.

- [ ] **Step 1: Write the new tests and update the existing ones**

Create `test/home/run.test.ts`:

```ts
import { readFileSync } from 'node:fs';
import { PassThrough } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { menuFor, renderStatus } from '../../src/home/run.js';
import { suggestNext } from '../../src/home/next.js';
import type { LastScan, ProjectStatus } from '../../src/home/status.js';
import { SnapshotStore } from '../../src/host/store.js';
import { initProject } from '../../src/project/init.js';
import { PromptCancelled } from '../../src/ui/prompt.js';
import { createStyle } from '../../src/ui/style.js';
import { runWizard, type WizardDeps } from '../../src/wizard/run.js';
import { FIXED_NOW } from '../helpers/ctx.js';
import { repoWith } from '../helpers/git.js';
import { ScriptedPrompter } from '../helpers/prompter.js';
import { FAKE } from '../helpers/secrets.js';
import { startHttps, useServers } from '../helpers/servers.js';
import { tempDir } from '../helpers/tmp.js';

const track = useServers();
const CONSENT = 'I own these systems or have written permission to test them';
const SCAN: LastScan = { at: '2026-10-28T10:00:00.000Z', ageDays: 1, verdict: { tone: 'green', text: 'No issues found' }, open: [], urgent: 0, unverifiable: 0 };

function status(over: Partial<ProjectStatus> = {}): ProjectStatus {
  return { name: 'shop', stack: ['nextjs'], git: true, lastScan: SCAN, websites: [], servers: [], unscanned: [], accepted: [], pendingLessons: 0, checklistExported: true, ...over };
}

function setup(answers: unknown[], extra: Partial<WizardDeps> = {}) {
  const out = new PassThrough();
  let printed = '';
  out.on('data', (c: Buffer) => {
    printed += c.toString();
  });
  const prompter = new ScriptedPrompter(answers);
  const deps: WizardDeps = { prompter, out, style: createStyle({ isTTY: false }), now: () => FIXED_NOW, openFile: async () => true, ...extra };
  return { prompter, deps, text: () => printed };
}

describe('the home screen', () => {
  it('says where things stand and what is next', () => {
    const s = status({
      websites: [{ id: 'shop', url: 'https://shop.example.com', env: 'prod' }],
      servers: [{ name: 'web-1', address: '203.0.113.10', env: 'prod', collector: 'none' }],
    });
    const text = renderStatus(s, suggestNext(s), createStyle({ isTTY: false }));
    expect(text).toContain('secagent · shop  (nextjs, git)');
    expect(text).toContain('Last scan   yesterday · No issues found');
    expect(text).toContain('Websites    https://shop.example.com (prod)');
    expect(text).toContain('Servers     web-1 (prod) · no collector output yet');
    expect(text).toContain('Next: web-1 has no collector output yet');
  });

  it('puts the suggestion first, marks it, and shows only what applies (nine items for a code-only project)', () => {
    const s = status({ lastScan: { ...SCAN, open: [['high', 2]], urgent: 2 } });
    const menu = menuFor(s, suggestNext(s));
    expect(menu.map((c) => c.value)).toEqual(['fixes', 'scan', 'report', 'checklist', 'risks', 'ai', 'settings', 'help', 'exit']);
    expect(menu[0]?.hint).toBe('suggested · 2 open');
  });

  it('with servers, lessons and accepted risks it shows every item: twelve', () => {
    const s = status({
      lastScan: { ...SCAN, open: [['medium', 1]] },
      servers: [{ name: 'web-1', address: '203.0.113.10', env: 'prod', collector: 'fresh' }],
      accepted: [{ findingId: 'a@code', owner: 'Sam', reason: 'vendor fix pending', expires: '2026-12-31', daysLeft: 60 }],
      pendingLessons: 1,
    });
    expect(menuFor(s, suggestNext(s))).toHaveLength(12);
  });

  it('before any scan the first item is "Run the first scan" and there is nothing to fix or open', () => {
    const s = status({ lastScan: undefined });
    const menu = menuFor(s, suggestNext(s));
    expect(menu[0]).toMatchObject({ value: 'scan', label: 'Run the first scan' });
    expect(menu.map((c) => c.value)).not.toContain('report');
    expect(menu.map((c) => c.value)).not.toContain('fixes');
  });

  it('a new session opens the home screen; Scan again asks for consent once, then reuses it', async () => {
    const server = await track(startHttps((_req, res) => res.end('ok')));
    const dir = await tempDir();
    const first = setup([undefined, undefined, ['web'], server.url, true, 'web', 'dev', false, 'office', true, 'exit']);
    expect(await runWizard(dir, first.deps)).toBe(0);
    const second = setup(['scan', true, 'scan', 'exit']);
    expect(await runWizard(dir, second.deps)).toBe(0);
    second.prompter.done();
    expect(second.prompter.asked).not.toContain('Shall we start?');
    expect(second.prompter.asked.filter((m) => m === CONSENT)).toHaveLength(1);
    expect(second.prompter.asked.filter((m) => m === 'What do you want to do?')).toHaveLength(3);
  });

  it('an action that fails says why and comes back to the home screen', async () => {
    const dir = await tempDir();
    await initProject(dir, { hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }] });
    await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', readFileSync(new URL('../fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8'));
    // Five hours earlier, the only collector output is dated in the future: verify cannot use it.
    const before = () => new Date(FIXED_NOW.getTime() - 5 * 3_600_000);
    const { prompter, deps, text } = setup(['verify', undefined, 'CVE-2024-6387', '', 'exit'], { now: before });
    expect(await runWizard(dir, deps)).toBe(0);
    prompter.done();
    expect(text()).toContain('dated in the future');
    expect(prompter.asked.filter((m) => m === 'What do you want to do?')).toHaveLength(2);
  });

  it('Settings: check this machine, and change what is checked (then it scans)', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'src/app.ts': `const id = '${FAKE.awsKeyId}';\n` });
    await initProject(dir);
    const reachable = (async () => new Response('{}', { status: 200 })) as typeof fetch;
    const { prompter, deps, text } = setup(['settings', 'doctor', 'settings', 'change', undefined, ['code'], 'exit'], { fetchImpl: reachable });
    expect(await runWizard(dir, deps)).toBe(0);
    prompter.done();
    expect(text()).toContain('✓ Node');
    expect(text()).toContain("I'm running 5 checks on your code.");
    expect(text()).not.toContain(FAKE.awsKeyId);
  });

  it('Ctrl+C on the home screen exits 130', async () => {
    const dir = await tempDir();
    await initProject(dir);
    const { deps, text } = setup([new PromptCancelled()]);
    expect(await runWizard(dir, deps)).toBe(130);
    expect(text()).toContain('Cancelled');
  });
});
```

Update `test/wizard/run.test.ts`. The first run now starts with the intro question (scripted `undefined` takes its default, "Set up and scan"), and the end menu is the home screen:

| Test | Old answers | New answers |
|---|---|---|
| code only: saves the settings... | `[undefined, ['code'], 'exit']` | `[undefined, undefined, ['code'], 'exit']` |
| a website: probes only after consent... | `[undefined, ['web'], server.url, true, 'web', 'dev', false, 'office', true, 'exit']` | prepend `undefined` |
| declined consent probes nothing... | `[undefined, ['web'], server.url, true, 'web', 'dev', false, 'office', false, 'quit']` | prepend `undefined` |
| Scan again re-runs the scan... | `[undefined, ['code'], 'again', 'exit']` | `[undefined, undefined, ['code'], 'scan', 'exit']` |
| Open the report opens the PDF... | `[undefined, ['code'], 'open', 'exit']` | `[undefined, undefined, ['code'], 'report', 'pdf', 'exit']` |
| says where the report is when it cannot open it | `[undefined, ['code'], 'open', 'exit']` | `[undefined, undefined, ['code'], 'report', 'pdf', 'exit']` |
| on a project that is already set up... | first `[undefined, ['code'], 'exit']`, second `['again', 'exit']` | first `[undefined, undefined, ['code'], 'exit']`, second `['scan', 'exit']` |
| the end menu can accept a risk... | `[undefined, ['code'], 'accept', id, ...]` | `[undefined, undefined, ['code'], 'risks', 'accept', id, 'Priya', 'rotating the key next sprint', '2026-12-15', 'lessons', 'approve', 'Priya', 'exit']` |

Also in "Scan again re-runs the scan...", change `prompter.asked.filter((m) => m.startsWith('What next?'))` to `prompter.asked.filter((m) => m === 'What do you want to do?')` (still 2), and rename "the end menu can accept a risk..." to "the home screen can accept a risk (the scan then runs again and lists it) and review a proposed lesson". Then add two tests to its `describe`:

```ts
  it('the first run says what secagent does and can show a guide before setting up', async () => {
    const dir = await leakyRepo();
    const { prompter, deps, text } = setup(['guides', 'servers', '', undefined, undefined, ['code'], 'exit']);
    expect(await runWizard(dir, deps)).toBe(0);
    prompter.done();
    expect(text()).toContain('I never log in, guess passwords or change anything.');
    expect(text()).toContain('Checking a server');
  });

  it('quitting at the intro saves nothing', async () => {
    const dir = await tempDir();
    const { deps, text } = setup(['quit']);
    expect(await runWizard(dir, deps)).toBe(0);
    expect(text()).toContain('Nothing was saved');
    expect(existsSync(path.join(dir, '.secagent'))).toBe(false);
  });
```

Update `test/cli.test.ts`: `const answers = () => new ScriptedPrompter([undefined, ['code'], 'exit']);` → `new ScriptedPrompter([undefined, undefined, ['code'], 'exit'])`.

Update `test/demo.test.ts`: prepend `undefined` to the `ScriptedPrompter` answers.

Update `test/wizard/questions.test.ts`, `describe('an existing project')`. The select is gone, and `start` defaults to `again`:

| Test | Change |
|---|---|
| Scan again asks only for consent | answers `[true]`; `deps({ existing: existing(), start: 'again' })`; `asked` is `['I own these systems or have written permission to test them']` |
| Change settings starts from the current answers | drop the leading `'change'` answer; `start: 'change'`; drop `'This project is already set up. What now?'` from `asked` |
| declining consent on Scan again can fall back to the code only... | answers `[false, 'code']`; `start: 'again'` |
| declining consent on Scan again can go back into the questions | drop the leading `'again'`; `start: 'again'` |
| Start over asks everything again with nothing kept | answers `['newname', ['code']]`; `start: 'fresh'` |

The two `start:` tests added in Task 4 now overlap with these; delete them.

- [ ] **Step 2: Run the tests to verify they fail**

Run: `npx vitest run test/home/run.test.ts test/wizard test/cli.test.ts test/demo.test.ts`
Expected: FAIL: `src/home/run.js` does not exist, and the wizard still shows its old menus.

- [ ] **Step 3: Drop the "already set up" question from `askPlan`**

In `src/wizard/questions.ts`, replace the whole `const action = deps.start ?? await p.select({ ... });` statement with:

```ts
    const action = deps.start ?? 'again';
```

and change the `start` comment in `AskDeps` to:

```ts
  /** For a project that is already set up: scan again with its settings (default), change them, or start over. */
```

- [ ] **Step 4: Add `scanAndReport` to `src/wizard/steps.ts`**

Add the imports `import { loadReportInput } from '../report/model.js';` (merge it into the existing `../report/model.js` import) and `import { writeReport } from '../report/write.js';`, remove `export` from `scanWithProgress` and `showResult` (only `scanAndReport` uses them now), and add:

```ts
/** Scans with live progress, writes the Markdown, PDF and HTML report, and shows the verdict and where the report is. */
export async function scanAndReport(dir: string, plan: WizardPlan, deps: WizardDeps): Promise<void> {
  const { out, style } = deps;
  const record = await scanWithProgress(dir, plan, deps);
  const input = await loadReportInput(dir);
  if (!input) throw new Error('the scan did not leave a record to report on');
  const [md, pdf, html] = (await writeReport(dir, input, { formats: ['md', 'pdf', 'html'] })).latest;
  showResult(record, input, deps);
  out.write(`\n${style.bold('Report')}\n  Markdown: ${md}\n  PDF:      ${pdf}\n  HTML:     ${html}\n`);
}
```

- [ ] **Step 5: Write `src/home/run.ts`**

```ts
import { ObservationError } from '../checks/errors.js';
import { KbError } from '../kb/lesson.js';
import { loadProject } from '../project/schema.js';
import { ScopeError } from '../project/scope.js';
import type { Choice } from '../ui/prompt.js';
import type { Style } from '../ui/style.js';
import { askPlan, type AskDeps, type WizardPlan } from '../wizard/questions.js';
import { askDepsFor, reviewLessons, savePlan, scanAndReport, type WizardDeps } from '../wizard/steps.js';
import { acceptedRisks, addCollectorOutput, checkCveClaim, checkSetup, connectAi, exportChecklist, openReport, showFixes, showGuides } from './actions.js';
import { suggestNext, type HomeAction, type Suggestion } from './next.js';
import { projectStatus, type ProjectStatus } from './status.js';

export interface HomeSession {
  /** The plan this session scanned with: a rescan reuses it, and its consent, without asking again. */
  plan?: WizardPlan;
}

const LABEL: Record<HomeAction, string> = {
  fixes: 'See what to fix first',
  scan: 'Scan again',
  report: 'Open the report',
  checklist: "Review what the scan can't see",
  collector: "Add a server's collector output",
  risks: 'Accepted risks',
  verify: "Check a scanner's CVE claim",
  lessons: 'Review lessons an AI assistant proposed',
  ai: 'Connect an AI assistant',
  settings: 'Settings and setup',
  help: 'How secagent works',
  exit: 'Exit',
};

function ago(days: number): string {
  return days === 0 ? 'today' : days === 1 ? 'yesterday' : `${days} days ago`;
}

/** The status block: what is set up, how the last scan went, and the suggested next step with its reason. */
export function renderStatus(s: ProjectStatus, next: Suggestion, style: Style): string {
  const lines = [`${style.bold(`secagent · ${s.name}`)}  ${style.dim(`(${[s.stack.length > 0 ? s.stack.join(', ') : 'stack not detected', s.git ? 'git' : 'no git'].join(', ')})`)}`, ''];
  const row = (label: string, text: string) => lines.push(`  ${label.padEnd(11)} ${text}`);
  const scan = s.lastScan;
  if (scan) {
    const counts = scan.open.map(([severity, n]) => `${severity} ${n}`).join(', ');
    row('Last scan', [ago(scan.ageDays), scan.verdict.text, ...(counts ? [counts] : []), ...(scan.unverifiable > 0 ? [`${scan.unverifiable} could not be checked`] : [])].join(' · '));
  } else row('Last scan', 'never');
  row('Websites', s.websites.length > 0 ? s.websites.map((w) => `${w.url} (${w.env})`).join(', ') : 'none listed');
  const collector = { none: ' · no collector output yet', stale: ' · collector output is stale', fresh: '' } as const;
  row('Servers', s.servers.length > 0 ? s.servers.map((h) => `${h.name} (${h.env})${collector[h.collector]}`).join(', ') : 'none listed');
  const soonest = s.accepted[0];
  if (soonest) row('Accepted', `${s.accepted.length} risk(s); the soonest ends ${soonest.daysLeft === 0 ? 'today' : `in ${soonest.daysLeft} day(s)`}`);
  if (s.pendingLessons > 0) row('Lessons', `${s.pendingLessons} waiting for your review`);
  lines.push('', `  ${style.bold('Next:')} ${next.text}`, '');
  return `\n${lines.join('\n')}\n`;
}

/** The menu: only items that apply, the suggested one first. */
export function menuFor(s: ProjectStatus, next: Suggestion): Array<Choice<HomeAction>> {
  const open = s.lastScan?.open.reduce((n, [, count]) => n + count, 0) ?? 0;
  const items: Array<[HomeAction, boolean, string | undefined]> = [
    ['fixes', open > 0, `${open} open`],
    ['scan', true, undefined],
    ['report', s.lastScan !== undefined, undefined],
    ['checklist', true, 'a checklist for you or your AI'],
    ['collector', s.servers.length > 0, undefined],
    ['risks', open > 0 || s.accepted.length > 0, s.accepted.length > 0 ? `${s.accepted.length} accepted` : undefined],
    ['verify', s.servers.length > 0, undefined],
    ['lessons', s.pendingLessons > 0, `${s.pendingLessons} waiting`],
    ['ai', true, undefined],
    ['settings', true, 'change what is checked, start over, check this machine'],
    ['help', true, 'step-by-step guides'],
    ['exit', true, undefined],
  ];
  const choices = items
    .filter(([, shown]) => shown)
    .map(([value, , hint]) => {
      const label = value === 'scan' && !s.lastScan ? 'Run the first scan' : LABEL[value];
      const marked = [...(value === next.action ? ['suggested'] : []), ...(hint ? [hint] : [])].join(' · ');
      return { value, label, ...(marked ? { hint: marked } : {}) };
    });
  return [...choices.filter((c) => c.value === next.action), ...choices.filter((c) => c.value !== next.action)];
}

/** Runs an action; an error the person can do something about is shown, and the home screen comes back. */
async function softly<T>(deps: WizardDeps, run: () => Promise<T>): Promise<T | undefined> {
  try {
    return await run();
  } catch (e) {
    if (!(e instanceof ObservationError || e instanceof KbError || e instanceof ScopeError)) throw e;
    deps.out.write(`${deps.style.red(e.message)}\n`);
    return undefined;
  }
}

/** Scans with this session's plan. Without one (a new session), or with new settings, it asks first, consent included. */
async function scanAgain(dir: string, deps: WizardDeps, session: HomeSession, start: NonNullable<AskDeps['start']>): Promise<void> {
  const now = deps.now ?? (() => new Date());
  let plan = start === 'again' ? session.plan : undefined;
  if (!plan) {
    plan = await askPlan(deps.prompter, await askDepsFor(dir, now, { existing: await loadProject(dir), start }));
    if (!plan) {
      deps.out.write('Nothing was changed and nothing was scanned.\n');
      return;
    }
    await savePlan(dir, plan, now);
    session.plan = plan;
  }
  await scanAndReport(dir, plan, deps);
}

async function settings(dir: string, deps: WizardDeps, session: HomeSession): Promise<void> {
  const choice = await deps.prompter.select({
    message: 'Settings and setup',
    choices: [
      { value: 'change' as const, label: 'Change what is checked', hint: 'websites, servers, network; then scan' },
      { value: 'fresh' as const, label: 'Start over', hint: 'every question again; then scan' },
      { value: 'doctor' as const, label: 'Check this machine', hint: 'Node, git, the project, the advisory database' },
      { value: 'back' as const, label: 'Back' },
    ],
    default: 'back' as const,
  });
  if (choice === 'change' || choice === 'fresh') await scanAgain(dir, deps, session, choice);
  else if (choice === 'doctor') await checkSetup(dir, deps);
}

/** The home screen: status, the suggested next step, the menu; again after every action, until Exit. */
export async function runHome(dir: string, deps: WizardDeps, session: HomeSession): Promise<number> {
  const { prompter, out, style } = deps;
  const now = deps.now ?? (() => new Date());
  for (;;) {
    const status = await projectStatus(dir, now());
    const next = suggestNext(status);
    out.write(renderStatus(status, next, style));
    prompter.discardPending?.();
    const action = await prompter.select({ message: 'What do you want to do?', choices: menuFor(status, next), default: next.action });
    switch (action) {
      case 'exit':
        return 0;
      case 'scan':
        await scanAgain(dir, deps, session, 'again');
        break;
      case 'settings':
        await settings(dir, deps, session);
        break;
      case 'risks':
        if (await softly(deps, () => acceptedRisks(dir, deps))) await scanAgain(dir, deps, session, 'again');
        break;
      case 'fixes':
        await softly(deps, () => showFixes(dir, deps));
        break;
      case 'report':
        await softly(deps, () => openReport(dir, deps));
        break;
      case 'checklist':
        await softly(deps, () => exportChecklist(dir, deps));
        break;
      case 'collector':
        await softly(deps, () => addCollectorOutput(dir, deps, next.host));
        break;
      case 'verify':
        await softly(deps, () => checkCveClaim(dir, deps));
        break;
      case 'lessons':
        await softly(deps, () => reviewLessons(dir, deps, now));
        break;
      case 'ai':
        connectAi(dir, deps);
        break;
      case 'help':
        await showGuides(deps);
        break;
    }
  }
}
```

- [ ] **Step 6: Rewrite `src/wizard/run.ts`**

```ts
import { CatalogError } from '../checks/catalog.js';
import { ObservationError } from '../checks/errors.js';
import { repoState } from '../code/git.js';
import { showGuides } from '../home/actions.js';
import { runHome } from '../home/run.js';
import { KbError } from '../kb/lesson.js';
import { loadProject, ProjectConfigError, projectFile } from '../project/schema.js';
import { ScopeError } from '../project/scope.js';
import { detectStack } from '../project/stack.js';
import { PromptCancelled } from '../ui/prompt.js';
import { askPlan } from './questions.js';
import { askDepsFor, exists, savePlan, scanAndReport, type WizardDeps } from './steps.js';

export type { WizardDeps } from './steps.js';

const INTRO = [
  "I look at your project the way an attacker's first pass would, then tell you what to fix first.",
  '  • Code: secrets, .env and key files, git history, npm packages',
  '  • Websites and APIs you give me: headers, TLS, cookies, exposed files',
  '  • Servers you give me: SSH, nginx, packages (you run a read-only script on them)',
  '',
  'I never log in, guess passwords or change anything. I only send read-only requests, only to',
  'addresses you list, and only after you say I may. Secret values are never printed.',
].join('\n');

/**
 * `secagent` on a terminal. First run: what secagent does, the setup questions, the first scan, then the home screen. Later runs go
 * straight to the home screen. Returns the exit code: 0 done, 130 cancelled, 1 for a problem with the settings or the scan.
 */
export async function runWizard(dir: string, deps: WizardDeps): Promise<number> {
  const { prompter, out, style } = deps;
  const now = deps.now ?? (() => new Date());
  try {
    if (await exists(projectFile(dir))) {
      try {
        await loadProject(dir);
      } catch (e) {
        if (!(e instanceof ProjectConfigError)) throw e;
        out.write(`${style.red(e.message)}\nFix it, or delete it to start over.\n`);
        return 1;
      }
      return await runHome(dir, deps, {});
    }

    out.write(`\n${style.bold('secagent')} · security check for this project\n`);
    const detection = await detectStack(dir);
    const git = await repoState(dir);
    const stack = Object.values(detection.stack).filter((v): v is string => typeof v === 'string');
    out.write(`  Folder: ${dir}\n  Stack: ${stack.length > 0 ? stack.join(', ') : 'not detected'}\n  Git: ${git.state === 'repo' ? 'repository' : 'not a repository'}\n\n${INTRO}\n\n`);
    for (;;) {
      const go = await prompter.select({
        message: 'Shall we start?',
        choices: [
          { value: 'setup' as const, label: 'Set up and scan this project' },
          { value: 'guides' as const, label: 'How secagent works first' },
          { value: 'quit' as const, label: 'Quit' },
        ],
        default: 'setup' as const,
      });
      if (go === 'setup') break;
      if (go === 'quit') {
        out.write('Nothing was saved and nothing was scanned.\n');
        return 0;
      }
      await showGuides(deps);
    }

    const plan = await askPlan(prompter, await askDepsFor(dir, now, { detection }));
    if (!plan) {
      out.write('Nothing was saved and nothing was scanned.\n');
      return 0;
    }
    await savePlan(dir, plan, now);
    await scanAndReport(dir, plan, deps);
    return await runHome(dir, deps, { plan });
  } catch (e) {
    if (e instanceof PromptCancelled) {
      out.write('\nCancelled.\n');
      return 130;
    }
    if (e instanceof ProjectConfigError || e instanceof ScopeError || e instanceof CatalogError || e instanceof ObservationError || e instanceof KbError) {
      out.write(`${style.red(e.message)}\n`);
      return 1;
    }
    throw e;
  }
}
```

- [ ] **Step 7: Run the tests to verify they pass**

Run: `npx vitest run test/home test/wizard test/cli.test.ts test/demo.test.ts`
Expected: PASS.

- [ ] **Step 8: Typecheck, full tests, commit**

```bash
npm run typecheck && npm test
git add src/home src/wizard test/home test/wizard test/cli.test.ts test/demo.test.ts
git commit -m "feat(home): home screen with status, next step and menu; first run opens with an intro"
```

---

### Task 7: Docs, build, and a smoke run

**Files:**
- Modify: `README.md`, `docs/usage.md`, `docs/overview.md`, `AGENTS.md`
- Modify: `docs/superpowers/specs/2026-10-30-secagent-home-and-help-design.md` (status line)

**Interfaces:** none.

- [ ] **Step 1: README**

In `README.md` "Use it", replace `Run \`secagent\` again in the same folder to scan again, change the answers, or start over.` with:

```markdown
Run `secagent` again in the same folder for the home screen: where the project stands (last scan, open issues, servers waiting for collector output, accepted risks about to end), the step it suggests next and why, and a menu for everything else: what to fix first, scan again, the review checklist for what the scan can't see, a server's collector output, a scanner's CVE claim, connecting an AI assistant, settings.

Help is built in: `secagent help` (where to start, and every command by task), `secagent help <command>` or `secagent <command> --help`, and step-by-step guides: `secagent help first-scan`, `servers`, `ai`, `ci`, `safety`.
```

In "Commands for scripts and CI", replace `` `secagent` with no command only starts the guided scan on a terminal; elsewhere it prints this list. `` with:

```markdown
`secagent` with no command starts the guided scan on a terminal; elsewhere it prints the help overview. Every command has a page: `secagent help <command>`.
```

- [ ] **Step 2: docs/usage.md**

Replace the paragraph starting `Then it scans with one line per check` and the "Run `secagent` again in the same folder and choose:" list after it (up to `## Scanning without questions`) with:

````markdown
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
````

Under `## Every command`, before the table, add:

```markdown
Every command has its own page: `secagent help <command>` or `secagent <command> --help`. Step-by-step guides: `secagent help first-scan`, `servers`, `ai`, `ci`, `safety`. A mistyped command gets a "Did you mean" suggestion.
```

and add this row to the table, after the `secagent version` row:

```markdown
| `secagent help [<command> \| <guide>]` | The overview, one command's page, or a guide |
```

- [ ] **Step 3: docs/overview.md and AGENTS.md**

In `docs/overview.md`, replace the "Guided scan" row of the layer table with:

```markdown
| Guided scan and home screen | `src/wizard/`, `src/home/`, `src/help/`, `src/ui/` | first-run intro, questions, consent, live progress; a home screen with the project's status, a suggested next step and every action; built-in help and guides; a small prompt layer on `node:readline` |
```

In `AGENTS.md` "Layout", add after the `src/wizard/`, `src/ui/` row:

```markdown
| `src/home/` | Home screen: status from local files, the suggested next step (fixed rules), actions that call the same functions as the CLI commands |
| `src/help/` | `secagent help`: command registry, guides, "did you mean" |
```

and to "Conventions":

```markdown
- A new command or option needs its entry in `src/help/commands.ts` and its options in `OPTIONS` in `src/cli.ts`; a test fails if they differ.
```

- [ ] **Step 4: Mark the spec implemented**

In the spec, change `- **Status:** design approved, implementation not started` to `- **Status:** implemented`.

- [ ] **Step 5: Verify everything**

```bash
npm run typecheck && npm test && npm run build
node dist/cli.js help
node dist/cli.js scan --help
node dist/cli.js help servers
node dist/cli.js chekclist; echo "exit $?"
```

Expected: typecheck clean; all tests pass; the overview starts with `secagent · finds what an attacker would hit first`; `scan --help` shows the scan page; `help servers` shows the guide; `chekclist` prints `Did you mean "checklist"?` and `exit 1`.

Then run the home screen by hand in a terminal (the harness has no TTY): `npm run demo:setup -- /tmp/secagent-demo && cd /tmp/secagent-demo && node <repo>/dist/cli.js`. Go through the intro, a code scan, the home screen, "See what to fix first", "Review what the scan can't see" and Exit.

- [ ] **Step 6: Commit**

```bash
git add README.md docs AGENTS.md
git commit -m "docs: home screen and built-in help in the README, usage guide, overview and AGENTS.md"
```

---

## Self-review against the spec

| Spec section | Task |
|---|---|
| §2 UI layer only, same functions, consent as today | 4 (moves only), 5 (same calls), 6 (`scanAgain`, consent tests) |
| §3 First run intro | 6 |
| §4.1 Status | 3 (`projectStatus`), 6 (`renderStatus`) |
| §4.2 Suggested next step, 7 rules in order | 3 |
| §4.3 Menu, conditional items, suggested first | 6 (`menuFor`); actions in 5 |
| §4.4 Checklist hand-off | 5 |
| §4.5 Errors return to the home screen; scan errors keep current handling | 6 (`softly`, `runWizard` catch) |
| §5 Agent voice | 4 (scan opening line), 5 and 6 (copy) |
| §6.1 Registry, options checked against parsers | 1, 2 |
| §6.2 Overview | 1, 2 |
| §6.3 Command pages, `--help` runs nothing, guides | 1, 2 |
| §6.4 Did you mean, usage hints, exit codes unchanged | 1, 2 |
| §8 Tests, including the secrets check on home output | 3, 5 (`not.toContain(FAKE.awsKeyId)`), 6 |
| §9 Docs | 7 |
