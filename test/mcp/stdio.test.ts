import path from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
import { describe, expect, it } from 'vitest';
import { initProject } from '../../src/project/init.js';
import { repoWith } from '../helpers/git.js';
import { FAKE } from '../helpers/secrets.js';
import { tempDir } from '../helpers/tmp.js';

const CLI = path.join(import.meta.dirname, '..', '..', 'src', 'cli.ts');
const TSX = path.join(import.meta.dirname, '..', '..', 'node_modules', '.bin', 'tsx');

describe('secagent mcp over stdio', () => {
  it('a real client can start it as a child process, list the tools and run a code scan; stdout stays protocol-only', async () => {
    const dir = await tempDir();
    await repoWith(dir, { 'src/app.ts': `// config\nconst id = '${FAKE.awsKeyId}';\n` });
    await initProject(dir, { name: 'shop', scanLabel: 'test-net' });

    const transport = new StdioClientTransport({ command: TSX, args: [CLI, 'mcp', '--dir', dir], stderr: 'pipe' });
    let stderr = '';
    transport.stderr?.on('data', (c: Buffer) => {
      stderr += c.toString();
    });
    const client = new Client({ name: 'secagent-e2e', version: '0.0.0' });
    await client.connect(transport);
    try {
      expect((await client.listTools()).tools.map((t) => t.name).sort()).toEqual(['get_evidence', 'get_findings', 'get_report', 'kb_read', 'kb_search', 'project_info', 'run_scan', 'verify_claim']);
      const info = await client.callTool({ name: 'project_info', arguments: {} });
      expect(JSON.parse((info.content as Array<{ text: string }>)[0]!.text).name).toBe('shop');
      const scan = await client.callTool({ name: 'run_scan', arguments: { groups: ['code'] } });
      expect(scan.isError).not.toBe(true);
      const text = (scan.content as Array<{ text: string }>)[0]!.text;
      expect(JSON.parse(text).findings.some((f: { observed?: string }) => f.observed?.includes('src/app.ts:2 aws-access-key-id'))).toBe(true);
      expect(text).not.toContain(FAKE.awsKeyId);
    } finally {
      await client.close();
    }
    expect(stderr).toBe('');
  }, 60_000);

  it('exits with a message, without starting, when the folder is not a secagent project', async () => {
    const dir = await tempDir();
    const transport = new StdioClientTransport({ command: TSX, args: [CLI, 'mcp', '--dir', dir], stderr: 'pipe' });
    const client = new Client({ name: 'secagent-e2e', version: '0.0.0' });
    await expect(client.connect(transport)).rejects.toThrow();
  }, 60_000);
});
