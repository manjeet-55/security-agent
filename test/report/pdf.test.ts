import { describe, expect, it } from 'vitest';
import { buildReport, type Block } from '../../src/report/model.js';
import { CELL_PAD, columnWidths, renderPdf } from '../../src/report/pdf.js';
import { fixtureInstances, fixtureProject, fixtureRecord } from './fixture.js';

const OPTS = { title: 'Security report: shop', footer: 'secagent · shop', createdAt: new Date('2026-10-28T10:00:00.000Z') };

function pages(pdf: Buffer): number {
  return (pdf.toString('latin1').match(/\/Type \/Page\b(?!s)/g) ?? []).length;
}

describe('renderPdf', () => {
  it('renders a whole report as a valid PDF', async () => {
    const pdf = await renderPdf(buildReport({ project: fixtureProject(), record: fixtureRecord(), instances: fixtureInstances() }), OPTS);
    expect(pdf.subarray(0, 5).toString('latin1')).toBe('%PDF-');
    expect(pdf.toString('latin1').trimEnd().endsWith('%%EOF')).toBe(true);
    expect(pages(pdf)).toBeGreaterThanOrEqual(1);
  });

  it('flows onto more pages when the report is long, repeating nothing it should not', async () => {
    const blocks: Block[] = [{ kind: 'title', text: 'Long', meta: 'meta' }];
    for (let i = 0; i < 60; i += 1) {
      blocks.push(
        { kind: 'heading', level: 3, text: `HIGH: Finding ${i}`, severity: 'high' },
        { kind: 'fields', items: [{ label: 'What we found', spans: [{ text: 'observed text '.repeat(20) }] }] },
      );
    }
    blocks.push({ kind: 'table', head: ['Check', 'Where', 'Reason'], rows: Array.from({ length: 80 }, (_v, i) => [`check ${i}`, 'somewhere', 'a reason that wraps '.repeat(4)]) });
    expect(pages(await renderPdf(blocks, OPTS))).toBeGreaterThan(3);
  });

  it('renders a six-column table, with long and short columns together, onto the page', async () => {
    const pdf = await renderPdf(
      [{ kind: 'table', head: ['Severity', 'Check', 'Where', 'Owner', 'Until', 'Reason'], rows: [['MEDIUM', 'Environment, key and credentials files are covered by .gitignore', "this project's code", 'Priya (dev lead)', '2026-12-15', 'server.key is a throwaway demo key, moves to the vault Friday']] }],
      OPTS,
    );
    expect(pages(pdf)).toBe(1);
  });

  it('copes with characters the built-in font does not have', async () => {
    const pdf = await renderPdf([{ kind: 'paragraph', spans: [{ text: 'arrow → check ✓ emoji 🔴 cjk 漢字' }] }], OPTS);
    expect(pages(pdf)).toBe(1);
  });
});

describe('columnWidths', () => {
  /** Every character is 5 points wide, so the numbers are easy to check. */
  const measure = (text: string) => text.length * 5;
  const TOTAL = 495;
  const HEAD = ['Severity', 'Check', 'Where', 'Owner', 'Until', 'Reason'];
  const ROW = ['MEDIUM', 'Environment, key and credentials files are covered by .gitignore', "this project's code", 'Priya (dev lead)', '2026-12-15', 'server.key is a throwaway demo key, moves to the vault Friday'];

  it('fills the page width exactly', () => {
    expect(columnWidths(measure, HEAD, [ROW], TOTAL).reduce((a, b) => a + b, 0)).toBeCloseTo(TOTAL, 6);
  });

  it('gives every column room for its longest word, so a header or a date never breaks mid-word', () => {
    const widths = columnWidths(measure, HEAD, [ROW], TOTAL);
    const longestWord = (c: number) => Math.max(...[HEAD[c] ?? '', ROW[c] ?? ''].flatMap((s) => s.split(/\s+/)).map(measure));
    widths.forEach((w, c) => expect(w, HEAD[c]).toBeGreaterThanOrEqual(longestWord(c) + 2 * CELL_PAD));
  });

  it('still gives the long text columns most of the width', () => {
    const [sev, check, , , until, reason] = columnWidths(measure, HEAD, [ROW], TOTAL) as [number, number, number, number, number, number];
    expect(check).toBeGreaterThan(sev * 2);
    expect(reason).toBeGreaterThan(until * 2);
  });

  it('caps the room a single very long word can claim, so one URL or id cannot squeeze the other columns', () => {
    const widths = columnWidths(measure, ['A', 'B'], [['x'.repeat(200), 'a short cell']], TOTAL);
    expect(widths[0]! + widths[1]!).toBeCloseTo(TOTAL, 6);
    expect(widths[1]).toBeGreaterThan(60);
  });

  it('falls back to proportional widths when the minimums cannot fit', () => {
    const widths = columnWidths(measure, ['a', 'b', 'c', 'd'], [['word'.repeat(20), 'word'.repeat(20), 'word'.repeat(20), 'word'.repeat(20)]], 200);
    expect(widths.reduce((a, b) => a + b, 0)).toBeCloseTo(200, 6);
    expect(Math.min(...widths)).toBeGreaterThan(0);
  });
});

