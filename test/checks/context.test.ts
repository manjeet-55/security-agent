import { describe, expect, it } from 'vitest';
import { getPage, subjectHostname, subjectId, subjectKind } from '../../src/checks/context.js';
import { fakeObs, hostSubject, makeCtx, targetSubject } from '../helpers/ctx.js';

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
  });
});
