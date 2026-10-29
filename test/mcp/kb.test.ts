import { describe, expect, it } from 'vitest';
import { connectMcp } from '../helpers/mcp.js';
import { makeProject } from '../helpers/project.js';
import { writeFiles } from '../helpers/tmp.js';

const NOW = () => new Date('2026-10-28T10:00:00.000Z');

describe('knowledge tools', () => {
  it('kb_search finds lessons and checks and says whether each is approved', async () => {
    const mcp = await connectMcp({ projectDir: await makeProject(), now: NOW });
    const s = await mcp.call('kb_search', { query: 'timeout firewall' });
    expect(s.isError).toBe(false);
    expect(s.json.hits[0]).toMatchObject({ id: 'unreachable-is-not-fixed', kind: 'lesson', review: 'approved' });
    expect((await mcp.call('kb_search', { query: 'hsts' })).json.hits.some((h: any) => h.id === 'hdr-hsts')).toBe(true);
    expect((await mcp.call('kb_search', { query: '', tags: ['nginx', 'proxy_buffer_size'] })).json.hits.map((h: any) => h.id)).toEqual(['header-budget-proxy-buffer']);
  });

  it('kb_read returns an entry, the generated INDEX, the project notes and the accepted risks', async () => {
    const mcp = await connectMcp({ projectDir: await makeProject(), now: NOW });
    expect((await mcp.call('kb_read', { id: 'unreachable-is-not-fixed' })).json.text).toContain('unverifiable');
    expect((await mcp.call('kb_read', { id: 'INDEX' })).json.text).toContain('## Lessons');
    expect((await mcp.call('kb_read', { id: 'notes' })).json.text).toContain('Project security notes');
    expect((await mcp.call('kb_read', { id: 'exceptions' })).json.text).toContain('exceptions: []');
  });

  it('kb_read of an unknown id is an error that points at kb_search, never a read of another file', async () => {
    const mcp = await connectMcp({ projectDir: await makeProject(), now: NOW });
    for (const id of ['nope', '../../project']) {
      const r = await mcp.call('kb_read', { id });
      expect(r.isError, id).toBe(true);
      expect(r.text).toContain('kb_search');
    }
  });

  it('serves the project\'s own lessons next to the global ones, and a broken one is an error result naming the file', async () => {
    const dir = await makeProject();
    const mcp = await connectMcp({ projectDir: dir, now: NOW });
    await writeFiles(dir, { '.secagent/knowledge/lessons/broken.md': 'no frontmatter' });
    const r = await mcp.call('kb_search', { query: 'backport' });
    expect(r.isError).toBe(true);
    expect(r.text).toContain('broken.md');
  });

  it('is read-only', async () => {
    const mcp = await connectMcp({ projectDir: await makeProject(), now: NOW });
    const tools = (await mcp.client.listTools()).tools;
    for (const name of ['kb_search', 'kb_read']) expect(tools.find((t) => t.name === name)?.annotations?.readOnlyHint, name).toBe(true);
  });
});
