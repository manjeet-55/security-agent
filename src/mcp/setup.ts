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
