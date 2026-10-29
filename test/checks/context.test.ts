import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../src/checks/errors.js';
import { getPage, getSnapshot, subjectHostname, subjectId, subjectKind } from '../../src/checks/context.js';
import { codeSubject, fakeObs, hostSubject, makeCtx, targetSubject } from '../helpers/ctx.js';
import { fixtureSnapshot, readerFor } from '../helpers/snapshots.js';

describe('check context', () => {
  it('fetches a target page once per scan and shares its evidence', async () => {
    let calls = 0;
    const { ctx } = await makeCtx({
      http: async (url) => {
        calls += 1;
        return fakeObs({ url });
      },
    });
    const a = await getPage(ctx, targetSubject(ctx));
    const b = await getPage(ctx, targetSubject(ctx));
    expect(calls).toBe(1);
    expect(a.evidenceId).toBe(b.evidenceId);
  });

  it('describes subjects', async () => {
    const { ctx } = await makeCtx();
    expect(subjectId(targetSubject(ctx))).toBe('app');
    expect(subjectKind(targetSubject(ctx))).toBe('web');
    expect(subjectHostname(targetSubject(ctx))).toBe('app.example.com');
    expect(subjectId(hostSubject(ctx))).toBe('web-1');
    expect(subjectKind(hostSubject(ctx))).toBe('host');
    expect(subjectHostname(hostSubject(ctx))).toBe('203.0.113.10');
    expect(subjectId(codeSubject('/tmp/x'))).toBe('code');
    expect(subjectKind(codeSubject('/tmp/x'))).toBe('code');
    expect(() => subjectHostname(codeSubject('/tmp/x'))).toThrow(/no network address/);
  });
});

describe('getSnapshot', () => {
  it('returns the newest snapshot and memoizes it', async () => {
    let calls = 0;
    const snapshot = fixtureSnapshot('ubuntu-24-04');
    const { ctx } = await makeCtx({}, {}, {
      snapshots: {
        latest: async () => {
          calls += 1;
          return { snapshot, file: '/x.json' };
        },
      },
    });
    await getSnapshot(ctx, hostSubject(ctx).host);
    await getSnapshot(ctx, hostSubject(ctx).host);
    expect(calls).toBe(1);
  });

  it('explains a missing snapshot and refuses a stale one', async () => {
    const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(undefined) });
    await expect(getSnapshot(ctx, hostSubject(ctx).host)).rejects.toMatchObject({ code: 'NO_SNAPSHOT' });
    const old = { ...fixtureSnapshot('debian-12'), collected_at: '2026-10-01T00:00:00Z' };
    const { ctx: ctx2 } = await makeCtx({}, {}, { snapshots: readerFor(old) });
    const err = await getSnapshot(ctx2, hostSubject(ctx2).host).catch((e: unknown) => e);
    expect(err).toBeInstanceOf(ObservationError);
    expect((err as ObservationError).code).toBe('SNAPSHOT_STALE');
  });

  it('refuses a future-dated snapshot as invalid', async () => {
    const future = { ...fixtureSnapshot('debian-12'), collected_at: '2026-10-28T17:00:00Z' };
    const { ctx } = await makeCtx({}, {}, { snapshots: readerFor(future) });
    await expect(getSnapshot(ctx, hostSubject(ctx).host)).rejects.toMatchObject({ code: 'SNAPSHOT_INVALID' });
  });
});
