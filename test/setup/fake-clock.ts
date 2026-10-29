import { vi } from 'vitest';

/**
 * `SECAGENT_TEST_NOW=2027-01-01T00:00:00Z npm test` runs the whole suite with the wall clock moved to that instant (Date only;
 * timers stay real). Fixtures are dated around 2026-10-28, so any test that reads the real clock for fixture-relative logic
 * (snapshot age, cache TTLs, certificate validity) fails under it instead of rotting silently later.
 */
const fake = process.env.SECAGENT_TEST_NOW;
if (fake) {
  const at = new Date(fake);
  if (Number.isNaN(at.getTime())) throw new Error(`SECAGENT_TEST_NOW is not a date: ${fake}`);
  vi.useFakeTimers({ toFake: ['Date'], now: at });
}
