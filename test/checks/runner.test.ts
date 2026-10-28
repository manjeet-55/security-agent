import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { z } from 'zod';
import { CheckInstanceSchema, type CheckInstance } from '../../src/checks/catalog.js';
import type { AnyCheckType, CheckType } from '../../src/checks/check-type.js';
import { subjectId } from '../../src/checks/context.js';
import { ObservationError } from '../../src/checks/errors.js';
import { runChecks, runInstance } from '../../src/checks/runner.js';
import { NetError } from '../../src/net/errors.js';
import { hostSubject, makeCtx, targetSubject } from '../helpers/ctx.js';

type Mode = 'pass' | 'fail' | 'neterror' | 'boom' | 'observe';
const fakeType: CheckType<{ mode: Mode }> = {
  type: 'fake',
  supports: ['web', 'api', 'host'],
  params: z.object({ mode: z.enum(['pass', 'fail', 'neterror', 'boom', 'observe']) }),
  async run(ctx, subject, p) {
    if (p.mode === 'neterror') throw new NetError('TIMEOUT', 'too slow');
    if (p.mode === 'observe') throw new ObservationError('NO_SNAPSHOT', 'No collector snapshot for host "web-1".');
    if (p.mode === 'boom') throw new Error('bug in check');
    const evidence_id = await ctx.evidence.put('note', subjectId(subject), `fake ${p.mode}`, {});
    return { outcome: p.mode, observed: `fake ${p.mode}`, evidence_id, ...(p.mode === 'fail' ? { severity: 'high' as const } : {}) };
  },
};
const TYPES = new Map<string, AnyCheckType>([['fake', fakeType]]);

function inst(id: string, mode: Mode, applies_to: string[] = ['web']): CheckInstance {
  return CheckInstanceSchema.parse({
    id,
    type: 'fake',
    title: id,
    severity: 'low',
    applies_to,
    params: { mode },
    source_url: 'https://example.com/guide',
    review: 'approved',
  });
}

describe('runInstance', () => {
  it('passes results through with the instance default severity', async () => {
    const { ctx } = await makeCtx();
    const r = await runInstance(ctx, targetSubject(ctx), inst('a', 'pass'), TYPES);
    expect(r).toMatchObject({ check_id: 'a', target: 'app', title: 'a', outcome: 'pass', severity: 'low', observed: 'fake pass' });
  });

  it('lets a check raise severity', async () => {
    const { ctx } = await makeCtx();
    expect((await runInstance(ctx, targetSubject(ctx), inst('a', 'fail'), TYPES)).severity).toBe('high');
  });

  it('turns network errors into unverifiable, with evidence and a reachability hint', async () => {
    const { ctx, dir } = await makeCtx();
    const r = await runInstance(ctx, hostSubject(ctx), inst('a', 'neterror', ['host']), TYPES);
    expect(r.outcome).toBe('unverifiable');
    expect(r.observed).toContain('test-net');
    expect(r.observed).toContain('office');
    expect(r.observed).toContain('does not mean the issue is fixed');
    expect(existsSync(path.join(dir, '.secagent', 'evidence', `${r.evidence_id}.json`))).toBe(true);
  });

  it('turns ObservationError into unverifiable without network wording', async () => {
    const { ctx } = await makeCtx();
    const r = await runInstance(ctx, hostSubject(ctx), inst('a', 'observe', ['host']), TYPES);
    expect(r.outcome).toBe('unverifiable');
    expect(r.observed).toBe('No collector snapshot for host "web-1". This does not mean the issue is fixed.');
  });

  it('turns check bugs into error', async () => {
    const { ctx } = await makeCtx();
    const r = await runInstance(ctx, targetSubject(ctx), inst('a', 'boom'), TYPES);
    expect(r.outcome).toBe('error');
    expect(r.observed).toContain('bug in check');
  });
});

describe('runChecks', () => {
  it('runs only the instances that apply to the subject kind', async () => {
    const { ctx } = await makeCtx();
    const instances = [inst('web-only', 'pass', ['web']), inst('host-only', 'pass', ['host'])];
    expect((await runChecks(ctx, targetSubject(ctx), instances, TYPES)).map((r) => r.check_id)).toEqual(['web-only']);
    expect((await runChecks(ctx, hostSubject(ctx), instances, TYPES)).map((r) => r.check_id)).toEqual(['host-only']);
  });
});
