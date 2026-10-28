import { existsSync, readFileSync } from 'node:fs';
import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { initProject } from '../../src/project/init.js';
import { loadProject, saveProject } from '../../src/project/schema.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

const APP = { id: 'app', url: 'https://app.example.com', type: 'web' as const, env: 'prod' };

describe('initProject', () => {
  it('creates the state tree, gitignore, knowledge files and project.yaml', async () => {
    const dir = await tempDir();
    await writeFiles(dir, { 'angular.json': '{}' });
    const r = await initProject(dir, { scanLabel: 'office', targets: [APP] });

    expect(r.created).toBe(true);
    for (const sub of ['hosts', 'external', 'evidence', 'findings/history', 'reports', 'knowledge']) {
      expect(existsSync(path.join(dir, '.secagent', sub))).toBe(true);
    }
    const gitignore = readFileSync(path.join(dir, '.secagent', '.gitignore'), 'utf8');
    for (const ignored of ['hosts/', 'external/', 'evidence/', 'findings/', 'reports/']) expect(gitignore).toContain(ignored);
    expect(existsSync(path.join(dir, '.secagent', 'knowledge', 'notes.md'))).toBe(true);
    expect(existsSync(path.join(dir, '.secagent', 'knowledge', 'exceptions.yaml'))).toBe(true);

    const p = await loadProject(dir);
    expect(p.name).toBe(path.basename(dir));
    expect(p.stack).toEqual({ frontend: 'angular' });
    expect(p.network.scan_label).toBe('office');
    expect(p.targets.map((t) => t.id)).toEqual(['app']);
  });

  it('keeps targets and user-set stack values when re-run, and fills in newly detected ones', async () => {
    const dir = await tempDir();
    await writeFiles(dir, { 'angular.json': '{}', 'nest-cli.json': '{}' });
    await initProject(dir, { targets: [APP] });
    const p = await loadProject(dir);
    await saveProject(dir, { ...p, stack: { frontend: 'vue' } });

    const r = await initProject(dir, { targets: [] });
    expect(r.created).toBe(false);
    expect(r.config.stack).toEqual({ frontend: 'vue', backend: 'nestjs' });
    expect(r.config.targets.map((t) => t.id)).toEqual(['app']);
  });

  it('never overwrites edited knowledge files', async () => {
    const dir = await tempDir();
    await initProject(dir);
    const notes = path.join(dir, '.secagent', 'knowledge', 'notes.md');
    await writeFile(notes, '# my notes\n');
    await initProject(dir);
    expect(readFileSync(notes, 'utf8')).toBe('# my notes\n');
  });
});
