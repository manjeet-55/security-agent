import { describe, expect, it } from 'vitest';
import { AdvisoryCache } from '../../src/advisories/cache.js';
import { distroOf } from '../../src/advisories/distro.js';
import type { FetchJson } from '../../src/advisories/fetch.js';
import { createAdvisories } from '../../src/advisories/index.js';
import { KevClient } from '../../src/advisories/kev.js';
import { hostPackageCheck, distroSources, findFixable } from '../../src/checks/types/host-package.js';
import { EvidenceStore } from '../../src/evidence/store.js';
import { decodeSnapshot } from '../../src/host/snapshot.js';
import { validateProject } from '../../src/project/schema.js';
import { verifyClaim } from '../../src/verify/claim.js';
import { fixtureFetch } from '../helpers/advisories.js';
import { hostSubject, makeCtx } from '../helpers/ctx.js';
import { fixtureEnvelope, readerFor } from '../helpers/snapshots.js';
import { tempDir } from '../helpers/tmp.js';

const DAY = 86_400_000;
const offline: FetchJson = async () => {
  throw new Error('offline');
};
const gate = () => {
  let open!: () => void;
  const promise = new Promise<void>((r) => (open = r));
  return { promise, open };
};

describe('AdvisoryCache.track', () => {
  it('reports the oldest as_of and any stale use for what was read inside the scope only', async () => {
    let now = new Date('2026-10-28T00:00:00Z');
    const cache = new AdvisoryCache(await tempDir(), () => now);
    await cache.getOrFetch('osv', 'a', 1000, async () => 1);
    now = new Date(now.getTime() + 5000);
    const { value, freshness } = await cache.track(async () => {
      await cache.getOrFetch('osv', 'b', 1000, async () => 2);
      await cache.getOrFetch('osv', 'a', 1000, async () => {
        throw new Error('offline');
      });
      return 'done';
    });
    expect(value).toBe('done');
    expect(freshness).toEqual({ as_of: '2026-10-28T00:00:00.000Z', stale: true });
    expect((await cache.track(async () => undefined)).freshness).toBeUndefined();
  });

  it('does not leak between concurrent scopes, however their reads interleave', async () => {
    let now = new Date('2026-10-20T00:00:00Z');
    const cache = new AdvisoryCache(await tempDir(), () => now);
    await cache.getOrFetch('osv', 'old', 1000, async () => 1);
    now = new Date('2026-10-28T00:00:00Z');
    await cache.getOrFetch('osv', 'new', 1_000_000_000, async () => 2);
    const gStale = gate();
    const gFresh = gate();
    const staleScope = cache.track(async () => {
      await gStale.promise;
      await cache.getOrFetch('osv', 'old', 1000, async () => {
        throw new Error('offline');
      });
    });
    const freshScope = cache.track(async () => {
      await gFresh.promise;
      await cache.getOrFetch('osv', 'new', 1_000_000_000, async () => 3);
    });
    gFresh.open();
    const fresh = await freshScope;
    gStale.open();
    const stale = await staleScope;
    expect(fresh.freshness).toEqual({ as_of: '2026-10-28T00:00:00.000Z', stale: false });
    expect(stale.freshness).toEqual({ as_of: '2026-10-20T00:00:00.000Z', stale: true });
  });

  it('a nested scope also reports to the scope around it', async () => {
    let now = new Date('2026-10-20T00:00:00Z');
    const cache = new AdvisoryCache(await tempDir(), () => now);
    await cache.getOrFetch('osv', 'a', 1000, async () => 1);
    now = new Date('2026-10-28T00:00:00Z');
    const outer = await cache.track(async () => {
      await cache.getOrFetch('osv', 'b', 1000, async () => 2);
      return cache.track(() =>
        cache.getOrFetch('osv', 'a', 1000, async () => {
          throw new Error('offline');
        }),
      );
    });
    expect(outer.value.freshness).toEqual({ as_of: '2026-10-20T00:00:00.000Z', stale: true });
    expect(outer.freshness).toEqual({ as_of: '2026-10-20T00:00:00.000Z', stale: true });
  });

  it('counts a KEV catalog read, including one served from the in-memory copy', async () => {
    let now = new Date('2026-10-28T00:00:00Z');
    const cache = new AdvisoryCache(await tempDir(), () => now);
    const kev = new KevClient(fixtureFetch(), cache, () => now);
    const first = await cache.track(() => kev.catalog());
    expect(first.freshness).toEqual({ as_of: '2026-10-28T00:00:00.000Z', stale: false });
    now = new Date(now.getTime() + 3_600_000);
    const second = await cache.track(() => kev.catalog());
    expect(second.freshness).toEqual({ as_of: '2026-10-28T00:00:00.000Z', stale: false });
  });

  it('createAdvisories exposes track', async () => {
    const adv = createAdvisories({ cacheDir: await tempDir(), fetchJson: fixtureFetch(), now: () => new Date('2026-10-28T00:00:00Z') });
    const { value, freshness } = await adv.track(() => adv.kev.catalog());
    expect(value.size).toBeGreaterThan(0);
    expect(freshness).toEqual({ as_of: '2026-10-28T00:00:00.000Z', stale: false });
  });
});

describe('concurrent host_package and verify_claim keep their own freshness', () => {
  const host = validateProject({ version: 1, name: 't', hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }] }).hosts[0]!;
  const iso = (d: Date) => d.toISOString().replace(/\.\d+Z$/, 'Z');
  const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));

  /** Deterministic pseudo-random staggers (0 to 2 ms) so a failure can be replayed. */
  function staggers(count: number): number[] {
    let seed = 20_261_029;
    return Array.from({ length: count }, () => {
      seed = (seed * 1_103_515_245 + 12_345) % 2_147_483_648;
      return (seed % 2001) / 1000;
    });
  }

  async function once(delayMs: number) {
    const t0 = new Date('2026-10-20T00:00:00Z');
    const runAt = new Date(t0.getTime() + 10 * DAY);
    const collected = iso(new Date(runAt.getTime() - DAY));
    const S = decodeSnapshot({ ...fixtureEnvelope('ubuntu-22-04'), collected_at: collected });
    const F = decodeSnapshot({ ...fixtureEnvelope('ubuntu-24-04'), collected_at: collected });
    const dS = distroOf(S.os)!;
    const dF = distroOf(F.os)!;
    const dir = await tempDir();
    // S: only the querybatch answer is 10 days old (past its 3-day TTL); everything else was fetched half a day ago.
    await createAdvisories({ cacheDir: dir, fetchJson: fixtureFetch(), now: () => t0 }).osv.affected(dS.ecosystem, distroSources(S, dS.codename));
    const recent = createAdvisories({ cacheDir: dir, fetchJson: fixtureFetch(), now: () => new Date(runAt.getTime() - DAY / 2) });
    for (const q of distroSources(S, dS.codename)) await recent.osv.vulnsFor(dS.ecosystem, q);
    await findFixable(recent, dF.ecosystem, distroSources(F, dF.codename));
    await recent.kev.catalog();
    await recent.ubuntu.cve('CVE-2021-41617');

    const shared = createAdvisories({ cacheDir: dir, fetchJson: offline, now: () => runAt });
    const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(S), advisories: shared });
    ctx.now = () => runAt;
    const pkg = hostPackageCheck
      .run(ctx, hostSubject(ctx), hostPackageCheck.params.parse({ assert: 'advisories' }), {} as never)
      .then(() => 'no error', (e: unknown) => e as Error);
    await sleep(delayMs);
    const claim = verifyClaim(
      { host, snapshots: readerFor(F), advisories: shared, evidence: new EvidenceStore(await tempDir(), 't'), now: () => runAt },
      { cve: 'CVE-2021-41617' },
    );
    const [p, c] = await Promise.all([pkg, claim]);
    return { stale: p, claim: c };
  }

  it('the stale host_package result stays stale and the fresh claim stays fresh over 20 randomised staggers', async () => {
    for (const delay of staggers(20)) {
      const { stale, claim } = await once(delay);
      expect(stale, `stagger ${delay}`).toMatchObject({ code: 'ADVISORIES_STALE' });
      expect((stale as Error).message, `stagger ${delay}`).toContain('advisory data as of 2026-10-20 is stale');
      expect(claim.stale, `stagger ${delay}`).toBe(false);
      expect(claim.verdict, `stagger ${delay}`).toBe('not_affected');
      expect(Date.parse(claim.as_of as string), `stagger ${delay}`).toBeGreaterThan(Date.parse('2026-10-24T00:00:00Z'));
    }
  }, 60_000);
});
