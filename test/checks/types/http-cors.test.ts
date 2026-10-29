import { describe, expect, it } from 'vitest';
import { evaluateCors } from '../../../src/checks/types/http-cors.js';
import { fakeObs } from '../../helpers/ctx.js';

const O = 'https://cors-probe-1a2b3c4d.example';
const obs = (headers: Record<string, string>) => fakeObs({ headers });

describe('evaluateCors', () => {
  it.each([
    [{}, 'pass', undefined],
    [{ 'access-control-allow-origin': 'https://app.example.com' }, 'pass', undefined],
    [{ 'access-control-allow-origin': '*' }, 'pass', undefined],
    [{ 'access-control-allow-origin': O }, 'fail', 'medium'],
    [{ 'access-control-allow-origin': O, 'access-control-allow-credentials': 'true' }, 'fail', 'high'],
    [{ 'access-control-allow-origin': 'null', 'access-control-allow-credentials': 'true' }, 'fail', 'medium'],
    [{ 'access-control-allow-origin': '*', 'access-control-allow-credentials': 'true' }, 'fail', 'medium'],
  ])('%j → %s', (headers, outcome, severity) => {
    const v = evaluateCors(obs(headers), O);
    expect(v.outcome).toBe(outcome);
    expect(v.severity).toBe(severity);
  });
});
