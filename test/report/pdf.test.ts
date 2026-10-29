import { describe, expect, it } from 'vitest';
import { buildReport, type Block } from '../../src/report/model.js';
import { renderPdf } from '../../src/report/pdf.js';
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

  it('copes with characters the built-in font does not have', async () => {
    const pdf = await renderPdf([{ kind: 'paragraph', spans: [{ text: 'arrow → check ✓ emoji 🔴 cjk 漢字' }] }], OPTS);
    expect(pages(pdf)).toBe(1);
  });
});
