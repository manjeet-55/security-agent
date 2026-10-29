import { afterEach, describe, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import { formatScan, main, parseHostSpec, parseTargetSpec, UsageError } from '../src/cli.js';
import { COLLECTOR_PATH } from '../src/host/collector.js';
import { SnapshotStore } from '../src/host/store.js';
import { initProject } from '../src/project/init.js';
import { loadProject } from '../src/project/schema.js';
import { fixtureAdvisories } from './helpers/advisories.js';
import { FIXED_NOW } from './helpers/ctx.js';
import { tempDir, writeFiles } from './helpers/tmp.js';

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

describe('host commands', () => {
  async function projectWithHost(): Promise<string> {
    const dir = await tempDir();
    await initProject(dir, { hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod' }] });
    return dir;
  }

  it('collector prints the script to stdout and instructions to stderr', async () => {
    const out = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const dir = await projectWithHost();
    expect(await main(['collector', '--dir', dir, '--host', 'web-1'])).toBe(0);
    expect(out).toHaveBeenCalledWith(readFileSync(COLLECTOR_PATH, 'utf8'));
    expect(err).toHaveBeenCalledWith(expect.stringContaining('secagent snapshot add --host web-1 web-1.json'));
  });

  it('collector refuses hosts that are not in project.yaml', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['collector', '--dir', await projectWithHost(), '--host', 'nope'])).toBe(1);
    expect(err).toHaveBeenCalledWith(expect.stringContaining('Unknown host "nope"'));
  });

  it('snapshot add validates and stores collector output', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = await projectWithHost();
    const fixture = readFileSync(new URL('./fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8');
    await writeFiles(dir, { 'web-1.json': fixture, 'bad.json': '{}' });
    expect(await main(['snapshot', 'add', '--dir', dir, '--host', 'web-1', `${dir}/web-1.json`], { now: () => FIXED_NOW })).toBe(0);
    expect(log).toHaveBeenCalledWith(expect.stringContaining('Ubuntu 24.04'));
    expect((await new SnapshotStore(dir, () => FIXED_NOW).latest('web-1'))?.snapshot.os.codename).toBe('noble');
    vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['snapshot', 'add', '--dir', dir, '--host', 'web-1', `${dir}/bad.json`], { now: () => FIXED_NOW })).toBe(1);
  });

  it('verify prints a verdict using the stored snapshot', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = await projectWithHost();
    await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', readFileSync(new URL('./fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8'));
    const code = await main(['verify', '--dir', dir, '--host', 'web-1', '--cve', 'CVE-2024-6387'], { advisories: fixtureAdvisories(await tempDir()), now: () => FIXED_NOW });
    expect(code).toBe(0);
    expect(log).toHaveBeenCalledWith('CVE-2024-6387 on web-1: fixed_in_installed');
  });

  it('verify judges the snapshot age by the injected clock, not the wall clock', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = await projectWithHost();
    await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', readFileSync(new URL('./fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8'));
    const later = () => new Date(FIXED_NOW.getTime() + 20 * 86_400_000);
    expect(await main(['verify', '--dir', dir, '--host', 'web-1', '--cve', 'CVE-2024-6387'], { advisories: fixtureAdvisories(await tempDir()), now: later })).toBe(0);
    expect(log).toHaveBeenCalledWith('CVE-2024-6387 on web-1: unverifiable');
  });

  it('snapshot add rejects a future-dated snapshot by the injected clock', async () => {
    vi.spyOn(console, 'log').mockImplementation(() => {});
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const dir = await projectWithHost();
    const fixture = readFileSync(new URL('./fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8');
    await writeFiles(dir, { 'web-1.json': fixture });
    const before = () => new Date(FIXED_NOW.getTime() - 5 * 3_600_000);
    expect(await main(['snapshot', 'add', '--dir', dir, '--host', 'web-1', `${dir}/web-1.json`], { now: before })).toBe(1);
    expect(err).toHaveBeenCalledWith(expect.stringContaining('in the future'));
    expect(await main(['snapshot', 'add', '--dir', dir, '--host', 'web-1', `${dir}/web-1.json`], { now: () => FIXED_NOW })).toBe(0);
  });

  it('verify rejects a malformed --cve with a usage message and exit 1, not a stack trace', async () => {
    const err = vi.spyOn(console, 'error').mockImplementation(() => {});
    const dir = await projectWithHost();
    for (const bad of ['6387', 'CVE-24-1', 'cve-2024-6387; rm -rf']) {
      expect(await main(['verify', '--dir', dir, '--host', 'web-1', '--cve', bad])).toBe(1);
    }
    expect(err).toHaveBeenCalledWith(expect.stringContaining('--cve must look like CVE-2024-6387'));
  });

  it('learn warms the advisory cache for stored snapshots', async () => {
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const dir = await projectWithHost();
    await new SnapshotStore(dir, () => FIXED_NOW).add('web-1', readFileSync(new URL('./fixtures/collector/ubuntu-24-04.json', import.meta.url), 'utf8'));
    expect(await main(['learn', '--dir', dir], { advisories: fixtureAdvisories(await tempDir()), now: () => FIXED_NOW })).toBe(0);
    expect(log).toHaveBeenCalledWith(expect.stringMatching(/^web-1: \d+ packages checked against Ubuntu:24\.04:LTS/));
  });
});
