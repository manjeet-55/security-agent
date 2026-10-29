import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';
import { SnapshotStore } from '../../src/host/store.js';
import { fixtureAdvisories } from '../helpers/advisories.js';
import { FIXED_NOW } from '../helpers/ctx.js';
import { connectMcp } from '../helpers/mcp.js';
import { makeProject } from '../helpers/project.js';
import { tempDir } from '../helpers/tmp.js';

const FIXTURE = readFileSync(new URL('../fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8');

async function setup() {
  const dir = await makeProject();
  await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', FIXTURE);
  const mcp = await connectMcp({ projectDir: dir, now: () => FIXED_NOW, advisories: fixtureAdvisories(await tempDir()) });
  return { dir, mcp };
}

describe('verify_claim', () => {
  it('gives the deterministic verdict from the host snapshot and the distro advisories, with its evidence', async () => {
    const { mcp } = await setup();
    const r = await mcp.call('verify_claim', { host: 'web-1', cve: 'CVE-2024-6387' });
    expect(r.isError).toBe(false);
    expect(r.json).toMatchObject({ cve: 'CVE-2024-6387', host: 'web-1', verdict: 'fixed_in_installed' });
    expect(r.json.evidence_id).toMatch(/^ev_\d{8}T\d{6}Z_[0-9a-f]{8}$/);
    expect((await mcp.call('get_evidence', { id: r.json.evidence_id })).json.kind).toBe('advisory');
  });

  it('is unverifiable, not safe, when the snapshot is too old', async () => {
    const dir = await makeProject();
    await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', FIXTURE);
    const later = () => new Date(FIXED_NOW.getTime() + 20 * 86_400_000);
    const mcp = await connectMcp({ projectDir: dir, now: later, advisories: fixtureAdvisories(await tempDir()) });
    expect((await mcp.call('verify_claim', { host: 'web-1', cve: 'CVE-2024-6387' })).json.verdict).toBe('unverifiable');
  });

  it('only judges hosts listed in project.yaml, and only well-formed CVE ids', async () => {
    const { mcp } = await setup();
    const unknown = await mcp.call('verify_claim', { host: 'other', cve: 'CVE-2024-6387' });
    expect(unknown.isError).toBe(true);
    for (const cve of ['6387', 'CVE-24-1', 'cve-2024-6387; rm -rf']) {
      expect((await mcp.call('verify_claim', { host: 'web-1', cve })).isError, cve).toBe(true);
    }
  });

  it('is registered next to the scan tools and is not marked read-only (it writes evidence)', async () => {
    const { mcp } = await setup();
    expect(await mcp.tools()).toContain('verify_claim');
    expect((await mcp.client.listTools()).tools.find((t) => t.name === 'verify_claim')?.annotations?.readOnlyHint).not.toBe(true);
  });
});
