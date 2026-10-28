import { mkdir } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { loadProject, parseProject, ProjectConfigError, saveProject } from '../../src/project/schema.js';
import { tempDir } from '../helpers/tmp.js';

const VALID = `
version: 1
name: demo
targets:
  - id: portal
    url: https://portal.example.com
    type: web
    env: prod
hosts:
  - name: web-1
    address: 203.0.113.10
    env: prod
    serves: [portal]
`;

describe('project schema', () => {
  it('applies defaults', () => {
    const p = parseProject(VALID);
    expect(p.network).toEqual({ ip_family: 4, scan_label: 'unlabelled' });
    expect(p.stack).toEqual({});
    expect(p.targets[0]?.allow_private).toBe(false);
    expect(p.hosts[0]?.reachable_from).toEqual([]);
  });

  it('rejects non-http URLs', () => {
    expect(() => parseProject(VALID.replace('https://portal.example.com', 'ftp://portal.example.com'))).toThrow(
      /targets\.0\.url/,
    );
  });

  it('rejects duplicate target ids', () => {
    const dup = VALID.replace('hosts:', '  - id: portal\n    url: https://x.example.com\n    type: api\n    env: prod\nhosts:');
    expect(() => parseProject(dup)).toThrow(/duplicate target id "portal"/);
  });

  it('rejects serves entries that point at unknown targets', () => {
    expect(() => parseProject(VALID.replace('serves: [portal]', 'serves: [nope]'))).toThrow(/unknown target id "nope"/);
  });

  it('round-trips through save and load', async () => {
    const dir = await tempDir();
    await mkdir(path.join(dir, '.secagent'));
    const p = parseProject(VALID);
    await saveProject(dir, p);
    expect(await loadProject(dir)).toEqual(p);
  });

  it('explains a missing config', async () => {
    const dir = await tempDir();
    await expect(loadProject(dir)).rejects.toBeInstanceOf(ProjectConfigError);
    await expect(loadProject(dir)).rejects.toThrow(/secagent init/);
  });
});
