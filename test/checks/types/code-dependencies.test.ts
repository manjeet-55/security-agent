import { describe, expect, it } from 'vitest';
import { codeDependenciesCheck, codeDependenciesParams } from '../../../src/checks/types/code-dependencies.js';
import { ObservationError } from '../../../src/checks/errors.js';
import { parseNpmLockfile } from '../../../src/code/lockfile.js';
import { codeSubject, makeCtx, NO_ADVISORIES } from '../../helpers/ctx.js';
import { writeFiles } from '../../helpers/tmp.js';

const V3 = JSON.stringify({
  lockfileVersion: 3,
  packages: {
    '': { name: 'app' },
    'node_modules/lodash': { version: '4.17.15' },
    'node_modules/a/node_modules/lodash': { version: '4.17.21', dev: true },
    'node_modules/@scope/pkg': { version: '1.0.0', dev: true },
    'packages/local': { version: '0.0.1' },
    'node_modules/local': { link: true },
  },
});
const V1 = JSON.stringify({ lockfileVersion: 1, dependencies: { express: { version: '4.17.1', dependencies: { qs: { version: '6.7.0' } } }, jest: { version: '29.0.0', dev: true } } });

function advisories(hit: string[], fail = false) {
  return {
    ...NO_ADVISORIES,
    osv: {
      affected: async (_e: string, qs: ReadonlyArray<{ name: string }>) => {
        if (fail) throw new Error('network down');
        return new Set(qs.map((q) => q.name).filter((n) => hit.includes(n)));
      },
      vulnsFor: async (_e: string, q: { name: string }) => [{ id: `GHSA-${q.name}`, database_specific: { severity: q.name === 'lodash' ? 'CRITICAL' : 'HIGH' } }],
      vuln: async () => null,
    },
  };
}

async function run(files: Record<string, string>, adv = advisories([])) {
  const { ctx, dir } = await makeCtx({}, {}, { advisories: adv as never });
  await writeFiles(dir, files);
  return codeDependenciesCheck.run(ctx, codeSubject(dir), codeDependenciesParams.parse({ ecosystem: 'npm' }), {} as never);
}

describe('parseNpmLockfile', () => {
  it('reads v3 packages, nested and scoped, skipping links and non-node_modules entries', () => {
    expect(parseNpmLockfile(V3).map((p) => `${p.name}@${p.version}${p.dev ? ' dev' : ''}`)).toEqual(['@scope/pkg@1.0.0 dev', 'lodash@4.17.15', 'lodash@4.17.21 dev']);
  });
  it('reads v1 dependency trees', () => {
    expect(parseNpmLockfile(V1).map((p) => `${p.name}@${p.version}`)).toEqual(['express@4.17.1', 'jest@29.0.0', 'qs@6.7.0']);
  });
  it('rejects something that is not a lockfile', () => {
    expect(() => parseNpmLockfile('{"name":"x"}')).toThrow(/lockfileVersion/);
  });
});

describe('code_dependencies', () => {
  it('passes a project that is not an npm project', async () => {
    expect((await run({ 'main.go': 'package main\n' })).outcome).toBe('pass');
  });
  it('is unverifiable with package.json but no lockfile, or when OSV cannot be reached', async () => {
    await expect(run({ 'package.json': '{}' })).rejects.toBeInstanceOf(ObservationError);
    await expect(run({ 'package.json': '{}', 'package-lock.json': V3 }, advisories([], true))).rejects.toThrow(/could not be reached/);
  });
  it('fails on packages with advisories, naming them, critical when an advisory is', async () => {
    const out = await run({ 'package.json': '{}', 'package-lock.json': V3 }, advisories(['lodash']));
    expect(out).toMatchObject({ outcome: 'fail', severity: 'critical' });
    expect(out.observed).toContain('lodash@4.17.15 GHSA-lodash');
    expect(out.observed).toContain('lodash@4.17.21 (dev)');
  });
  it('passes when nothing has an advisory', async () => {
    expect((await run({ 'package.json': '{}', 'package-lock.json': V1 })).outcome).toBe('pass');
  });
});
