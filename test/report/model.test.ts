import { describe, expect, it } from 'vitest';
import { areaOf, buildReport, verdict, whereOf, type Block } from '../../src/report/model.js';
import { fixtureInstances, fixtureProject, fixtureRecord } from './fixture.js';

function build(overrides: Parameters<typeof fixtureRecord>[0] = {}): Block[] {
  return buildReport({ project: fixtureProject(), record: fixtureRecord(overrides), instances: fixtureInstances() });
}

function headings(blocks: Block[], level: 2 | 3): string[] {
  return blocks.filter((b): b is Extract<Block, { kind: 'heading' }> => b.kind === 'heading' && b.level === level).map((b) => b.text);
}

/** The blocks between a level-2 heading and the next one. */
function section(blocks: Block[], title: string): Block[] {
  const start = blocks.findIndex((b) => b.kind === 'heading' && b.level === 2 && b.text === title);
  if (start === -1) throw new Error(`no section ${title}`);
  const end = blocks.findIndex((b, i) => i > start && b.kind === 'heading' && b.level === 2);
  return blocks.slice(start + 1, end === -1 ? undefined : end);
}

const text = (spans: Array<{ text: string }>): string => spans.map((s) => s.text).join('');

describe('verdict', () => {
  const base = fixtureRecord();
  it('is red when anything critical or high is open', () => {
    expect(verdict(base)).toEqual({ tone: 'red', text: 'Needs attention: 1 high-priority issue(s)' });
  });
  it('is yellow when only lower severities are open', () => {
    const record = { ...base, findings: base.findings.filter((f) => f.severity !== 'high') };
    expect(verdict(record)).toEqual({ tone: 'yellow', text: 'Some issues to fix: 1 open' });
  });
  it('is yellow, not green, when nothing is open but something could not be verified', () => {
    const record = { ...base, findings: base.findings.filter((f) => f.status !== 'open') };
    expect(verdict(record)).toEqual({ tone: 'yellow', text: 'No issues found, but 1 check(s) could not be verified' });
  });
  it('is green only when nothing is open and everything was verified', () => {
    expect(verdict({ ...base, findings: base.findings.filter((f) => f.status === 'fixed') })).toEqual({ tone: 'green', text: 'No issues found' });
  });
});

describe('areaOf and whereOf', () => {
  const instances = fixtureInstances();
  it('sorts checks into code, websites and servers', () => {
    expect(areaOf(instances.get('code-leak'))).toBe('code');
    expect(areaOf(instances.get('hdr-hsts'))).toBe('web');
    expect(areaOf(instances.get('ssh-root'))).toBe('host');
  });
  it('names where a finding is in words', () => {
    const project = fixtureProject();
    expect(whereOf(project, 'code')).toBe("this project's code");
    expect(whereOf(project, 'portal')).toBe('https://portal.example.com');
    expect(whereOf(project, 'web-1')).toBe('web-1 (203.0.113.10)');
    expect(whereOf(project, 'gone')).toBe('gone');
  });
});

describe('buildReport', () => {
  it('starts with the title, meta line and verdict, then the sections in order', () => {
    const blocks = build();
    expect(blocks[0]).toEqual({ kind: 'title', text: 'Security report: shop', meta: 'Scanned 2026-10-28 10:00 UTC from network "office" · deterministic scan, no AI' });
    expect(blocks[1]).toEqual({ kind: 'verdict', tone: 'red', text: 'Needs attention: 1 high-priority issue(s)' });
    expect(headings(blocks, 2)).toEqual(['At a glance', 'Fix first', 'Findings', 'Could not verify', 'Fixed since the last scan', 'Passed', 'About this scan']);
  });

  it('counts checks, issues and gaps per area', () => {
    const table = section(build(), 'At a glance')[0];
    expect(table).toEqual({
      kind: 'table',
      head: ['Area', 'Checks', 'Issues', 'Could not check'],
      rows: [
        ['Code', '2', '1', '0'],
        ['Websites and APIs', '3', '1', '0'],
        ['Servers', '2', '0', '1'],
      ],
    });
  });

  it('leaves out areas that were not scanned', () => {
    const record = fixtureRecord();
    const blocks = build({ results: record.results.filter((r) => r.target === 'code'), findings: record.findings.filter((f) => f.target === 'code') });
    const table = section(blocks, 'At a glance')[0] as Extract<Block, { kind: 'table' }>;
    expect(table.rows.map((r) => r[0])).toEqual(['Code']);
  });

  it('lists what to fix first by severity, with where and the first line of the fix', () => {
    const list = section(build(), 'Fix first')[0] as Extract<Block, { kind: 'list' }>;
    expect(list.items.map(text)).toEqual([
      "Failed: code-leak title — this project's code — Fix code-leak like this.",
      'Failed: hdr-hsts title — https://portal.example.com — Fix hdr-hsts like this.',
    ]);
    expect(list.items[0]?.[0]).toMatchObject({ bold: true });
  });

  it('explains each open finding: where, what, why, how, learn more, evidence', () => {
    const findings = section(build(), 'Findings');
    expect(findings[0]).toEqual({ kind: 'heading', level: 3, text: 'Failed: code-leak title', severity: 'high' });
    const fields = findings[1] as Extract<Block, { kind: 'fields' }>;
    expect(fields.items.map((i) => i.label)).toEqual(['Where', 'What we found', 'Why it matters', 'How to fix', 'Learn more', 'Evidence']);
    const value = (label: string) => text(fields.items.find((i) => i.label === label)?.spans ?? []);
    expect(value('What we found')).toContain('src/a.ts:2 aws-access-key-id [1a2b3c4d]');
    expect(value('Why it matters')).toBe('A leaked key lets anyone use your account.');
    expect(value('How to fix')).toBe('Fix code-leak like this.\nSecond line.');
    expect(fields.items.find((i) => i.label === 'Learn more')?.spans[0]).toMatchObject({ href: 'https://docs.example.com/code-leak' });
    // a check without a "why" falls back to its title
    const second = findings[3] as Extract<Block, { kind: 'fields' }>;
    expect(text(second.items.find((i) => i.label === 'Why it matters')?.spans ?? [])).toBe('hdr-hsts title');
  });

  it('keeps Fix first to the first sentence of the fix, cut at 160 characters', () => {
    const record = fixtureRecord();
    const long = 'Rotate the key now, then ' + 'move it to the environment '.repeat(10) + 'please. Then a second sentence.';
    const findings = record.findings.map((f) => (f.check_id === 'code-leak' ? { ...f, fix: { where: 'any', how: `[any] ${long}`, side_effects: [] } } : f));
    const list = section(build({ findings }), 'Fix first')[0] as Extract<Block, { kind: 'list' }>;
    const first = text(list.items[0] ?? []);
    expect(first.endsWith('…')).toBe(true);
    expect(first.split(' — ')[2]?.length).toBeLessThanOrEqual(160);
    const short = text((section(build(), 'Fix first')[0] as Extract<Block, { kind: 'list' }>).items[0] ?? []);
    expect(short.endsWith('Fix code-leak like this.')).toBe(true);
  });

  it('names the stack on a stack-specific fix, and leaves the generic ones bare', () => {
    const record = fixtureRecord();
    const how = '[nginx] location ~ /\\. { deny all; }\n[apache] Require all denied\n[any] Remove the file.';
    const findings = record.findings.map((f) => (f.check_id === 'code-leak' ? { ...f, fix: { where: 'nginx, apache, any', how, side_effects: [] } } : f));
    const blocks = build({ findings });
    const fields = section(blocks, 'Findings')[1] as Extract<Block, { kind: 'fields' }>;
    expect(text(fields.items.find((i) => i.label === 'How to fix')?.spans ?? [])).toBe('nginx: location ~ /\\. { deny all; }\napache: Require all denied\nRemove the file.');
    const first = text((section(blocks, 'Fix first')[0] as Extract<Block, { kind: 'list' }>).items[0] ?? []);
    expect(first.endsWith('— nginx: location ~ /\\. { deny all; }')).toBe(true);
  });

  it('says so when nothing is open', () => {
    const record = fixtureRecord();
    const findings = section(build({ findings: record.findings.filter((f) => f.status !== 'open') }), 'Findings');
    expect(findings).toEqual([{ kind: 'paragraph', spans: [{ text: 'No open findings.' }] }]);
  });

  it('keeps what could not be verified apart from what passed, with the reason', () => {
    const gaps = section(build(), 'Could not verify');
    expect(gaps[0]).toEqual({
      kind: 'table',
      head: ['Check', 'Where', 'Reason'],
      rows: [['ssh-root title', 'web-1 (203.0.113.10)', 'No collector snapshot for host "web-1". This does not mean the issue is fixed.']],
    });
    expect(gaps[1]).toEqual({ kind: 'paragraph', spans: [{ text: 'These are not passes: fix the cause and scan again.' }] });
    const passed = section(build(), 'Passed')[0] as Extract<Block, { kind: 'list' }>;
    expect(passed.items.map(text)).toEqual([
      'Code: code-clean title',
      'Websites and APIs: hdr-csp title (https://portal.example.com), tls-ok title (https://portal.example.com)',
      'Servers: ssh-pass title (web-1 (203.0.113.10))',
    ]);
  });

  it('lists what was fixed since the last scan, and drops the section when nothing was', () => {
    const fixed = section(build(), 'Fixed since the last scan')[0] as Extract<Block, { kind: 'list' }>;
    expect(fixed.items.map(text)).toEqual(['tls-ok title — https://portal.example.com']);
    expect(headings(build({ diff: { new: [], fixed: [], regressed: [] } }), 2)).not.toContain('Fixed since the last scan');
  });

  it('states the scope, how consent was given, and the fail-closed and secrets rules', () => {
    const about = (blocks: Block[]) => (section(blocks, 'About this scan')[0] as Extract<Block, { kind: 'list' }>).items.map(text);
    const cli = about(build());
    expect(cli).toContain("Code: this project's folder");
    expect(cli).toContain('Websites and APIs: https://portal.example.com (prod)');
    expect(cli).toContain('Servers: web-1 (203.0.113.10, prod)');
    expect(cli).toContain('Run from the command line.');
    expect(cli).toContain('A check that could not run is never counted as passed.');
    expect(cli).toContain('Secret values are never shown, only the file, line and a fingerprint.');
    expect(about(build({ consent_at: '2026-10-28T09:59:00.000Z' }))).toContain('Scope confirmed by the person running the scan on 2026-10-28 09:59 UTC.');
  });
});
