import { describe, expect, it } from 'vitest';
import { createAdvisories } from '../../src/advisories/index.js';
import { tempDir } from '../helpers/tmp.js';

describe.runIf(process.env.SECAGENT_LIVE === '1')('live advisory sources (network)', () => {
  it('reach OSV, Ubuntu and CISA KEV', async () => {
    const a = createAdvisories({ cacheDir: await tempDir() });
    const ub = await a.ubuntu.cve('CVE-2024-6387');
    const noble = ub?.packages.find((p) => p.name === 'openssh')?.statuses.find((s) => s.release_codename === 'noble');
    expect(noble).toMatchObject({ status: 'released', description: '1:9.6p1-3ubuntu13.3' });
    expect([...(await a.osv.affected('Ubuntu:24.04:LTS', [{ name: 'openssh', version: '1:9.6p1-3ubuntu13' }]))]).toEqual(['openssh']);
    expect((await a.kev.catalog()).size).toBeGreaterThan(1000);
  }, 60_000);
});
