import { describe, expect, it } from 'vitest';
import { activeException, loadExceptions } from '../../src/kb/exceptions.js';
import { FIXED_NOW } from '../helpers/ctx.js';
import { makeProject } from '../helpers/project.js';
import { writeFiles } from '../helpers/tmp.js';

describe('exceptions.yaml', () => {
  it('is empty after init', async () => {
    expect(await loadExceptions(await makeProject())).toEqual([]);
  });

  it('loads entries and matches them by finding id until they expire (inclusive)', async () => {
    const dir = await makeProject();
    await writeFiles(dir, {
      '.secagent/knowledge/exceptions.yaml': 'exceptions:\n  - finding_id: hdr-csp@app\n    owner: dev-lead\n    reason: CSP rollout planned\n    expires: "2026-10-28"\n',
    });
    const list = await loadExceptions(dir);
    expect(activeException(list, 'hdr-csp@app', FIXED_NOW)?.owner).toBe('dev-lead');
    expect(activeException(list, 'hdr-csp@app', new Date('2026-10-29T00:00:00Z'))).toBeUndefined();
    expect(activeException(list, 'hdr-hsts@app', FIXED_NOW)).toBeUndefined();
  });

  it('names the field when an entry is invalid', async () => {
    const dir = await makeProject();
    await writeFiles(dir, { '.secagent/knowledge/exceptions.yaml': 'exceptions:\n  - finding_id: x\n    owner: y\n    reason: z\n' });
    await expect(loadExceptions(dir)).rejects.toThrow(/exceptions\.0\.expires/);
  });
});
