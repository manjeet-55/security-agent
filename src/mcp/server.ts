import { readFileSync } from 'node:fs';
import path from 'node:path';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { PACKAGE_ROOT } from '../paths.js';
import { ServerState, type ServerOptions } from './state.js';
import { registerProjectTools } from './tools/project.js';

/** Sent to the client when it connects; the rules that keep an AI assistant's statements tied to evidence. */
export const SERVER_INSTRUCTIONS = [
  'secagent runs deterministic security checks on one project. You explain and prioritise; the checks decide every status.',
  '- Call project_info first, then run_scan, before saying anything about the project\'s security state.',
  '- A finding is open, fixed or unverifiable only as the latest scan says. unverifiable means unknown, not safe.',
  '- Never say something is fixed or safe without a new scan that shows it. After a fix, call run_scan again.',
  '- Cite evidence ids (get_evidence) for what you report.',
  '- Secret values are never available to you and you must not ask for them: findings give file, line, pattern and a fingerprint only. Tell the person to rotate any credential reported.',
  '- You cannot change which websites or servers are probed; only a person editing .secagent/project.yaml can.',
].join('\n');

function version(): string {
  try {
    return (JSON.parse(readFileSync(path.join(PACKAGE_ROOT, 'package.json'), 'utf8')) as { version?: string }).version ?? '0.0.0';
  } catch {
    return '0.0.0';
  }
}

export function createMcpServer(opts: ServerOptions): { server: McpServer; state: ServerState } {
  const state = new ServerState(opts);
  const server = new McpServer({ name: 'secagent', version: version() }, { instructions: SERVER_INSTRUCTIONS });
  registerProjectTools(server, state);
  return { server, state };
}

/** Serves the project over stdio. stdout carries the protocol, so nothing else may print there. */
export async function runMcpStdio(opts: ServerOptions): Promise<void> {
  const { server } = createMcpServer(opts);
  await server.connect(new StdioServerTransport());
}
