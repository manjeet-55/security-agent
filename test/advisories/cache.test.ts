import { describe, expect, it } from 'vitest';
import { AdvisoryCache } from '../../src/advisories/cache.js';
import { ObservationError } from '../../src/checks/errors.js';
import { tempDir } from '../helpers/tmp.js';

describe('AdvisoryCache', () => {
  it('serves fresh entries without refetching and refetches after the TTL', async () => {
    let now = new Date('2026-10-28T00:00:00Z');
    const cache = new AdvisoryCache(await tempDir(), () => now);
    let calls = 0;
    const fetcher = async () => {
      calls += 1;
      return { n: calls };
    };
    expect((await cache.getOrFetch('osv', 'k', 1000, fetcher)).value).toEqual({ n: 1 });
    expect((await cache.getOrFetch('osv', 'k', 1000, fetcher)).value).toEqual({ n: 1 });
    now = new Date(now.getTime() + 2000);
    expect((await cache.getOrFetch('osv', 'k', 1000, fetcher)).value).toEqual({ n: 2 });
    expect(calls).toBe(2);
  });

  it('falls back to a stale copy when the source fails', async () => {
    let now = new Date('2026-10-28T00:00:00Z');
    const cache = new AdvisoryCache(await tempDir(), () => now);
    await cache.getOrFetch('kev', 'k', 1000, async () => ['CVE-1']);
    now = new Date(now.getTime() + 5000);
    const r = await cache.getOrFetch('kev', 'k', 1000, async () => {
      throw new Error('offline');
    });
    expect(r).toMatchObject({ value: ['CVE-1'], stale: true });
  });

  it('raises ADVISORY_UNAVAILABLE when the source fails and nothing is cached', async () => {
    const cache = new AdvisoryCache(await tempDir());
    const err = await cache
      .getOrFetch('ubuntu', 'k', 1000, async () => {
        throw new Error('offline');
      })
      .catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect((err as ObservationError).code).toBe('ADVISORY_UNAVAILABLE');
  });

  it('caches null (404) results too', async () => {
    const cache = new AdvisoryCache(await tempDir());
    let calls = 0;
    const fetcher = async () => {
      calls += 1;
      return null;
    };
    await cache.getOrFetch('ubuntu', 'CVE-0', 1000, fetcher);
    expect((await cache.getOrFetch('ubuntu', 'CVE-0', 1000, fetcher)).value).toBeNull();
    expect(calls).toBe(1);
  });
});
