import { afterEach, describe, expect, it, vi } from 'vitest';
import { formatScan, main, parseHostSpec, parseTargetSpec, UsageError } from '../src/cli.js';
import { loadProject } from '../src/project/schema.js';
import { tempDir } from './helpers/tmp.js';

afterEach(() => {
  vi.restoreAllMocks();
});

describe('spec parsers', () => {
  it('parses target and host specs', () => {
    expect(parseTargetSpec('app=https://app.example.com,web,prod')).toEqual({ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' });
    expect(parseHostSpec('web-1=203.0.113.10,prod')).toEqual({ name: 'web-1', address: '203.0.113.10', env: 'prod' });
  });
  it('rejects malformed specs with a usage error', () => {
    expect(() => parseTargetSpec('app=ftp://x,web,prod')).toThrow(UsageError);
    expect(() => parseHostSpec('web-1')).toThrow(UsageError);
  });
});

describe('main', () => {
  it('init writes targets and hosts from flags', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = await tempDir();
    const code = await main(['init', '--dir', dir, '--scan-label', 'office', '--target', 'app=https://app.example.com,web,prod', '--host', 'web-1=203.0.113.10,prod']);
    expect(code).toBe(0);
    const p = await loadProject(dir);
    expect(p.network.scan_label).toBe('office');
    expect(p.targets[0]).toMatchObject({ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' });
    expect(p.hosts[0]).toMatchObject({ name: 'web-1', address: '203.0.113.10', env: 'prod' });
  });

  it('scan without --no-ai explains how to run it', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['scan', '--dir', await tempDir()])).toBe(1);
    expect(error).toHaveBeenCalledWith(expect.stringContaining('secagent scan --no-ai'));
  });

  it('scan --no-ai before init points at init', async () => {
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['scan', '--no-ai', '--dir', await tempDir()])).toBe(1);
    expect(error).toHaveBeenCalledWith(expect.stringContaining('secagent init'));
  });

  it('rejects unknown commands and unknown flags', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['nope'])).toBe(1);
    expect(await main(['init', '--bogus'])).toBe(1);
  });

  it('prints usage with no command', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    expect(await main([])).toBe(0);
    expect(log).toHaveBeenCalledWith(expect.stringContaining('secagent <command>'));
  });
});

describe('formatScan', () => {
  it('lists findings most severe first with the observed text', () => {
    const EV = 'ev_20261028T100000Z_00000000';
    const T = '2026-10-28T10:00:00.000Z';
    const lines = formatScan({
      schema: 1, scanned_at: T, scan_label: 'office', mode: 'no-ai',
      results: [
        { check_id: 'a', target: 'app', title: 'a', outcome: 'fail', severity: 'low', observed: 'low thing', evidence_id: EV },
        { check_id: 'b', target: 'app', title: 'b', outcome: 'fail', severity: 'high', observed: 'big thing', evidence_id: EV },
      ],
      findings: (['a', 'b'] as const).map((c) => ({
        id: `${c}@app`, check_id: c, target: 'app', severity: c === 'a' ? ('low' as const) : ('high' as const), status: 'open' as const,
        title: c, evidence: [EV], reasoning: 'r', refs: [], knowledge: [], first_seen: T, last_seen: T, verified_at: T,
      })),
      diff: { new: ['a@app', 'b@app'], fixed: [], regressed: [] },
    });
    expect(lines[1]).toContain('open 2');
    expect(lines[2]).toContain('HIGH');
    expect(lines[2]).toContain('big thing');
    expect(lines[3]).toContain('LOW');
  });
});
