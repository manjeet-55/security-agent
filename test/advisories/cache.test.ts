import { writeFile } from 'node:fs/promises';
import path from 'node:path';
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

  it('returns the fetched value when the cache cannot be written', async () => {
    const blocker = path.join(await tempDir(), 'file');
    await writeFile(blocker, 'x');
    const cache = new AdvisoryCache(blocker);
    const r = await cache.getOrFetch('osv', 'k', 1000, async () => ({ ok: true }));
    expect(r).toMatchObject({ value: { ok: true }, stale: false });
  });

  it('handles concurrent fetches of the same key', async () => {
    const cache = new AdvisoryCache(await tempDir());
    const fetcher = async () => ({ ok: true });
    const [a, b] = await Promise.all([
      cache.getOrFetch('osv', 'k', 1000, fetcher),
      cache.getOrFetch('osv', 'k', 1000, fetcher),
    ]);
    expect(a.value).toEqual({ ok: true });
    expect(b.value).toEqual({ ok: true });
  });

  it('refuses a stale copy older than 30 days when the refresh fails', async () => {
    let now = new Date('2026-10-28T00:00:00Z');
    const cache = new AdvisoryCache(await tempDir(), () => now);
    await cache.getOrFetch('kev', 'k', 1000, async () => ['CVE-1']);
    const offline = async (): Promise<string[]> => {
      throw new Error('offline');
    };
    now = new Date(now.getTime() + 29 * 86_400_000);
    expect(await cache.getOrFetch('kev', 'k', 1000, offline)).toMatchObject({ stale: true });
    now = new Date(now.getTime() + 2 * 86_400_000);
    const err = await cache.getOrFetch('kev', 'k', 1000, offline).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect((err as ObservationError).code).toBe('ADVISORY_UNAVAILABLE');
    expect((err as ObservationError).message).toMatch(/31 days old/);
  });

  it('treats a fetched_at in the future as expired: refetches, and is unavailable if that fails', async () => {
    let now = new Date('2026-10-28T00:00:00Z');
    const dir = await tempDir();
    await new AdvisoryCache(dir, () => now).getOrFetch('kev', 'k', 1000 * 86_400, async () => 'old');
    now = new Date(now.getTime() - 3 * 3_600_000);
    const cache = new AdvisoryCache(dir, () => now);
    const offline = async (): Promise<string> => {
      throw new Error('offline');
    };
    await expect(cache.getOrFetch('kev', 'k', 1000 * 86_400, offline)).rejects.toMatchObject({ code: 'ADVISORY_UNAVAILABLE' });
    expect(await cache.getOrFetch('kev', 'k', 1000 * 86_400, async () => 'new')).toMatchObject({ value: 'new', stale: false });
  });

  it('freshness() reports the oldest as_of and any stale use, then resets', async () => {
    let now = new Date('2026-10-28T00:00:00Z');
    const cache = new AdvisoryCache(await tempDir(), () => now);
    await cache.getOrFetch('osv', 'a', 1000, async () => 1);
    cache.freshness();
    now = new Date(now.getTime() + 5000);
    await cache.getOrFetch('osv', 'b', 1000, async () => 2);
    await cache.getOrFetch('osv', 'a', 1000, async () => {
      throw new Error('offline');
    });
    expect(cache.freshness()).toEqual({ as_of: '2026-10-28T00:00:00.000Z', stale: true });
    expect(cache.freshness()).toBeUndefined();
  });
});
