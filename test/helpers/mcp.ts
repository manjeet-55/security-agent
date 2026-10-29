import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { InMemoryTransport } from '@modelcontextprotocol/sdk/inMemory.js';
import { onTestFinished } from 'vitest';
import { createMcpServer } from '../../src/mcp/server.js';
import type { ServerOptions, ServerState } from '../../src/mcp/state.js';

export interface ToolCall {
  isError: boolean;
  text: string;
  /** The parsed JSON text, or undefined when the text is not JSON. */
  json: any;
}

export interface Connected {
  client: Client;
  state: ServerState;
  call(name: string, args?: Record<string, unknown>): Promise<ToolCall>;
  tools(): Promise<string[]>;
}

/** A secagent MCP server and a client linked in memory; closed when the test finishes. */
export async function connectMcp(opts: ServerOptions): Promise<Connected> {
  const { server, state } = createMcpServer(opts);
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  const client = new Client({ name: 'secagent-test', version: '0.0.0' });
  await client.connect(clientTransport);
  onTestFinished(() => client.close());
  return {
    client,
    state,
    async call(name, args = {}) {
      const r = await client.callTool({ name, arguments: args });
      const text = (r.content as Array<{ type: string; text?: string }>).map((c) => c.text ?? '').join('');
      let json: unknown;
      try {
        json = JSON.parse(text);
      } catch {
        json = undefined;
      }
      return { isError: r.isError === true, text, json };
    },
    async tools() {
      return (await client.listTools()).tools.map((t) => t.name).sort();
    },
  };
}
