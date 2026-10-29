import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { PACKAGE_ROOT } from '../src/paths.js';

/** Fixture dates sit around 2026-10-28, so anything that compares them with the real clock stops passing a few days later. */
const FUTURE = '2027-01-01T00:00:00Z';
const TEST_DIR = path.join(PACKAGE_ROOT, 'test');

/** Test files that may read the wall clock, and why. */
const ALLOWED_WALL_CLOCK = new Map([
  ['advisories/fetch.test.ts', 'measures elapsed time against a deadline, not a date'],
  ['checks/types/tls.test.ts', 'real TLS handshakes: OpenSSL validates the test certificate against the system clock'],
]);

function testSources(dir: string): string[] {
  return readdirSync(dir, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) return entry.name === 'fixtures' ? [] : testSources(full);
    return entry.name.endsWith('.ts') ? [full] : [];
  });
}

describe('the suite does not depend on the wall clock', () => {
  it('no test or helper reads the real clock unless it is listed with a reason', () => {
    const offenders = testSources(TEST_DIR)
      .map((file) => path.relative(TEST_DIR, file))
      .filter((rel) => rel !== 'clock-guard.test.ts' && !ALLOWED_WALL_CLOCK.has(rel))
      .filter((rel) => /new Date\(\)|Date\.now\(\)/.test(readFileSync(path.join(TEST_DIR, rel), 'utf8')));
    expect(offenders, 'inject a fixed `now` (see FIXED_NOW in test/helpers/ctx.ts) instead of reading the real clock').toEqual([]);
  });

  // Runs the rest of the suite with Date moved to 2027-01-01 (test/setup/fake-clock.ts). Code that reaches the real clock on
  // its own (a default `() => new Date()`) is caught here even when no test mentions the clock.
  it.skipIf(process.env.SECAGENT_TEST_NOW !== undefined)(
    `the rest of the suite passes with the system clock at ${FUTURE}`,
    () => {
      const vitest = path.join(PACKAGE_ROOT, 'node_modules', 'vitest', 'vitest.mjs');
      const run = spawnSync(process.execPath, [vitest, 'run', '--exclude', 'test/clock-guard.test.ts'], {
        cwd: PACKAGE_ROOT,
        env: { ...process.env, SECAGENT_TEST_NOW: FUTURE },
        encoding: 'utf8',
        timeout: 180_000,
      });
      const tail = `${run.stdout}${run.stderr}`.split('\n').slice(-40).join('\n');
      expect(run.status, `a test depends on the real clock:\n${tail}`).toBe(0);
    },
    200_000,
  );
});
