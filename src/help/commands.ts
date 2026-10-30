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
