import { describe, expect, it } from 'vitest';
import { loadCheckInstances } from '../../src/checks/catalog.js';
import { CHECK_TYPES } from '../../src/checks/registry.js';
import type { ExposedPathParams } from '../../src/checks/types/exposed-path.js';
import { GLOBAL_CHECKS_DIR } from '../../src/paths.js';

async function signature(path: string): Promise<RegExp> {
  const instance = (await loadCheckInstances(GLOBAL_CHECKS_DIR, CHECK_TYPES)).find((c) => c.id === 'exposed-paths');
  const entry = (instance?.params as ExposedPathParams | undefined)?.paths.find((p) => p.path === path);
  if (!entry) throw new Error(`exposed-paths has no ${path}`);
  return new RegExp(entry.signature, 'm');
}

describe('exposed-paths seed signatures', () => {
  it('recognise env files, Spring Actuator env and Apache server-status, and not an HTML error page', async () => {
    const html404 = '<!doctype html><html><head><title>Not found</title></head><body><h1>Page not found</h1></body></html>';
    for (const path of ['/.env.production', '/.env.local']) {
      expect((await signature(path)).test('# prod\nDATABASE_URL=postgres://x\n'), path).toBe(true);
      expect((await signature(path)).test(html404), path).toBe(false);
    }
    const actuator = await signature('/actuator/env');
    expect(actuator.test('{"activeProfiles":["prod"],"propertySources":[{"name":"server.ports"}]}')).toBe(true);
    expect(actuator.test('{"status":"UP"}')).toBe(false);
    const status = await signature('/server-status');
    expect(status.test('<html><head><title>Apache Status</title></head><body><h1>Apache Server Status for example.com (via 10.0.0.5)</h1>')).toBe(true);
    expect(status.test(html404)).toBe(false);
  });
});
