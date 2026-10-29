import { describe, expect, it } from 'vitest';
import { activeException, exceptionFor, loadExceptions } from '../../src/kb/exceptions.js';
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

  it('exceptionFor prefers an active entry, else the most recently expired one, and says which it is', () => {
    const list = [
      { finding_id: 'a@x', owner: 'old', reason: 'r', expires: '2026-01-01' },
      { finding_id: 'a@x', owner: 'older', reason: 'r', expires: '2025-06-01' },
      { finding_id: 'b@x', owner: 'now', reason: 'r', expires: '2026-12-31' },
      { finding_id: 'b@x', owner: 'gone', reason: 'r', expires: '2026-01-01' },
    ];
    expect(exceptionFor(list, 'a@x', FIXED_NOW)).toMatchObject({ owner: 'old', expired: true });
    expect(exceptionFor(list, 'b@x', FIXED_NOW)).toMatchObject({ owner: 'now', expired: false });
    expect(exceptionFor(list, 'c@x', FIXED_NOW)).toBeUndefined();
  });

  it('names the field when an entry is invalid', async () => {
    const dir = await makeProject();
    await writeFiles(dir, { '.secagent/knowledge/exceptions.yaml': 'exceptions:\n  - finding_id: x\n    owner: y\n    reason: z\n' });
    await expect(loadExceptions(dir)).rejects.toThrow(/exceptions\.0\.expires/);
  });
});
