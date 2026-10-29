import { describe, expect, it } from 'vitest';
import { doctor } from '../src/doctor.js';
import { FIXED_NOW } from './helpers/ctx.js';
import { makeProject } from './helpers/project.js';
import { tempDir } from './helpers/tmp.js';

const reachable = (async () => new Response('{}', { status: 200 })) as typeof fetch;
const unreachable = (async () => { throw new Error('offline'); }) as typeof fetch;
const text = (lines: Awaited<ReturnType<typeof doctor>>) => lines.map((l) => `${l.level}: ${l.text}`).join('\n');

describe('doctor', () => {
  it('flags an old Node and an unset folder, and says what to run', async () => {
    const lines = await doctor(await tempDir(), { now: () => FIXED_NOW, nodeVersion: '18.19.0', fetchImpl: reachable });
    expect(lines[0]).toMatchObject({ level: 'fail', fix: expect.stringContaining('20.19') });
    expect(lines.find((l) => l.text.includes('not set up'))?.fix).toBe('Run: secagent');
  });

  it('describes a set-up project, warns about missing snapshots and consent, and about an unreachable OSV', async () => {
    const dir = await makeProject();
    const lines = await doctor(dir, { now: () => FIXED_NOW, nodeVersion: '20.19.0', fetchImpl: unreachable });
    const out = text(lines);
    expect(out).toContain('ok: Project "test": 1 website(s), 1 server(s)');
    expect(out).toContain('warn: No collector snapshot for server web-1');
    expect(out).toContain('warn: No scan yet');
    expect(out).toContain('warn: The advisory database (OSV) is not reachable');
    expect(lines.some((l) => l.level === 'fail')).toBe(false);
  });

  it('--offline skips the network check', async () => {
    const lines = await doctor(await makeProject(), { now: () => FIXED_NOW, offline: true, fetchImpl: unreachable });
    expect(text(lines)).not.toContain('OSV');
  });
});
