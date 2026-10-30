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
