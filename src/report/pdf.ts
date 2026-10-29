import PDFDocument from 'pdfkit';
import type { Severity } from '../types.js';
import type { Block, Span, Tone } from './model.js';

export interface PdfOptions {
  title: string;
  footer: string;
  createdAt: Date;
}

type Doc = InstanceType<typeof PDFDocument>;

const MARGIN = 50;
const BODY = 10;
const SMALL = 9;
const INK = '#101828';
const MUTED = '#475467';
const LINK = '#175cd3';
const RULE = '#d0d5dd';
const HEAD_BG = '#f2f4f7';

const TONE_COLOUR: Record<Tone, string> = { red: '#b42318', yellow: '#b54708', green: '#067647' };
const SEVERITY_COLOUR: Record<Severity, string> = { critical: '#7a271a', high: '#b42318', medium: '#b54708', low: '#175cd3', info: '#475467' };

/** Characters the built-in fonts can draw are Latin-1 plus a few WinAnsi extras; the rest are spelled out or replaced. */
const REPLACEMENTS: Record<string, string> = { '→': '->', '←': '<-', '✓': 'OK', '✗': 'x', '…': '...', '•': '•', '—': '—', '–': '–', '·': '·' };
function safe(text: string): string {
  let out = '';
  for (const ch of text) {
    const code = ch.codePointAt(0) ?? 0;
    if (REPLACEMENTS[ch] !== undefined) out += REPLACEMENTS[ch];
    else if (code === 0x0a || (code >= 0x20 && code <= 0x7e) || (code >= 0xa0 && code <= 0xff) || '‘’“”€'.includes(ch)) out += ch;
    else out += '?';
  }
  return out;
}

function contentWidth(doc: Doc): number {
  return doc.page.width - doc.page.margins.left - doc.page.margins.right;
}

function bottom(doc: Doc): number {
  return doc.page.height - doc.page.margins.bottom;
}

/** Starts a new page when less than `needed` points are left on this one. */
function ensureSpace(doc: Doc, needed: number): void {
  if (doc.y + needed > bottom(doc)) doc.addPage();
}

/** Writes spans as one flowing paragraph starting at x, wrapping within width. */
function writeSpans(doc: Doc, spans: readonly Span[], x: number, width: number, size = BODY): void {
  const parts = spans.filter((s) => s.text !== '');
  if (parts.length === 0) return;
  doc.x = x;
  parts.forEach((s, i) => {
    doc
      .font(s.code ? 'Courier' : s.bold ? 'Helvetica-Bold' : 'Helvetica')
      .fontSize(size)
      .fillColor(s.href ? LINK : INK);
    const opts = { width, continued: i < parts.length - 1, ...(s.href ? { link: s.href, underline: true } : { link: null, underline: false }) };
    if (i === 0) doc.text(safe(s.text), x, doc.y, opts);
    else doc.text(safe(s.text), opts);
  });
  doc.fillColor(INK);
}

function title(doc: Doc, b: Extract<Block, { kind: 'title' }>): void {
  doc.font('Helvetica-Bold').fontSize(20).fillColor(INK).text(safe(b.text), MARGIN, doc.y, { width: contentWidth(doc) });
  doc.moveDown(0.2);
  doc.font('Helvetica').fontSize(SMALL).fillColor(MUTED).text(safe(b.meta), { width: contentWidth(doc) });
  doc.fillColor(INK).moveDown(0.8);
}

function verdict(doc: Doc, b: Extract<Block, { kind: 'verdict' }>): void {
  const width = contentWidth(doc);
  doc.font('Helvetica-Bold').fontSize(12);
  const height = doc.heightOfString(safe(b.text), { width: width - 24 }) + 16;
  ensureSpace(doc, height);
  const y = doc.y;
  doc.roundedRect(MARGIN, y, width, height, 4).fill(TONE_COLOUR[b.tone]);
  doc.fillColor('#ffffff').text(safe(b.text), MARGIN + 12, y + 8, { width: width - 24 });
  doc.fillColor(INK);
  doc.y = y + height;
  doc.moveDown(0.6);
}

function heading(doc: Doc, b: Extract<Block, { kind: 'heading' }>): void {
  const width = contentWidth(doc);
  if (b.level === 2) {
    ensureSpace(doc, 70);
    doc.moveDown(0.6);
    doc.font('Helvetica-Bold').fontSize(14).fillColor(INK).text(safe(b.text), MARGIN, doc.y, { width });
    const y = doc.y + 2;
    doc.moveTo(MARGIN, y).lineTo(MARGIN + width, y).lineWidth(0.5).strokeColor(RULE).stroke();
    doc.y = y + 6;
    return;
  }
  ensureSpace(doc, 60);
  doc.moveDown(0.4);
  let x = MARGIN;
  if (b.severity) {
    const label = b.severity.toUpperCase();
    doc.font('Helvetica-Bold').fontSize(8);
    const w = doc.widthOfString(label) + 10;
    const y = doc.y;
    doc.roundedRect(x, y, w, 13, 3).fill(SEVERITY_COLOUR[b.severity]);
    doc.fillColor('#ffffff').text(label, x + 5, y + 3, { lineBreak: false });
    doc.y = y;
    x += w + 6;
  }
  doc.font('Helvetica-Bold').fontSize(11.5).fillColor(INK).text(safe(b.text), x, doc.y, { width: MARGIN + width - x });
  doc.moveDown(0.3);
}

function paragraph(doc: Doc, b: Extract<Block, { kind: 'paragraph' }>): void {
  writeSpans(doc, b.spans, MARGIN, contentWidth(doc));
  doc.moveDown(0.5);
}

function bulleted(doc: Doc, items: readonly Span[][]): void {
  const width = contentWidth(doc);
  for (const spans of items) {
    ensureSpace(doc, 16);
    const y = doc.y;
    doc.font('Helvetica').fontSize(BODY).fillColor(MUTED).text('•', MARGIN + 2, y, { lineBreak: false });
    doc.y = y;
    writeSpans(doc, spans, MARGIN + 14, width - 14);
    doc.moveDown(0.25);
  }
  doc.x = MARGIN;
  doc.moveDown(0.3);
}

function fields(doc: Doc, b: Extract<Block, { kind: 'fields' }>): void {
  bulleted(
    doc,
    b.items.map((i) => [{ text: `${i.label}: `, bold: true }, ...i.spans]),
  );
}

export const CELL_PAD = 4;
/** The most room a single unbreakable word may claim, and the most a column asks for to show its longest cell on one line. */
const MAX_WORD = 110;
const MAX_FULL = 300;

/** Width in points of a string in the table font; the header is set in bold. */
export type Measure = (text: string, bold: boolean) => number;

/**
 * Column widths that fill `total`: every column gets room for its longest word (so a header or a date never breaks mid-word),
 * then the room it would need to show its longest cell on one line, with what is left shared in proportion. When even the
 * minimums do not fit, the columns share the width in proportion to how much text they hold.
 */
export function columnWidths(measure: Measure, head: readonly string[], rows: readonly string[][], total: number): number[] {
  const cellsOf = (c: number) => [{ text: head[c] ?? '', bold: true }, ...rows.map((r) => ({ text: r[c] ?? '', bold: false }))];
  const min = head.map((_h, c) => Math.min(MAX_WORD, Math.max(0, ...cellsOf(c).flatMap((x) => x.text.split(/\s+/).map((w) => measure(w, x.bold))))) + 2 * CELL_PAD);
  const full = head.map((_h, c) => Math.max(min[c] ?? 0, Math.min(MAX_FULL, Math.max(0, ...cellsOf(c).map((x) => measure(x.text, x.bold)))) + 2 * CELL_PAD));
  const sum = (xs: readonly number[]) => xs.reduce((a, b) => a + b, 0);
  if (sum(min) >= total) {
    const share = head.map((_h, c) => Math.max(1, ...cellsOf(c).map((x) => x.text.length)));
    return share.map((w) => (w / sum(share)) * total);
  }
  const spare = total - sum(min);
  const want = full.map((f, c) => f - (min[c] ?? 0));
  if (sum(want) <= spare) {
    const leftover = total - sum(full);
    return full.map((f) => f + (leftover * f) / sum(full));
  }
  return min.map((m, c) => m + (spare * (want[c] ?? 0)) / sum(want));
}

function rowHeight(doc: Doc, cells: readonly string[], widths: readonly number[], header: boolean): number {
  doc.font(header ? 'Helvetica-Bold' : 'Helvetica').fontSize(SMALL);
  return Math.max(...cells.map((c, i) => doc.heightOfString(safe(c), { width: (widths[i] ?? 0) - CELL_PAD * 2 }))) + CELL_PAD * 2;
}

function tableRow(doc: Doc, cells: readonly string[], widths: readonly number[], header: boolean): void {
  const height = rowHeight(doc, cells, widths, header);
  const y = doc.y;
  const width = widths.reduce((a, b) => a + b, 0);
  if (header) doc.rect(MARGIN, y, width, height).fill(HEAD_BG);
  let x = MARGIN;
  cells.forEach((c, i) => {
    doc.fillColor(INK).text(safe(c), x + CELL_PAD, y + CELL_PAD, { width: (widths[i] ?? 0) - CELL_PAD * 2 });
    x += widths[i] ?? 0;
  });
  doc.moveTo(MARGIN, y + height).lineTo(MARGIN + width, y + height).lineWidth(0.5).strokeColor(RULE).stroke();
  doc.x = MARGIN;
  doc.y = y + height;
}

function table(doc: Doc, b: Extract<Block, { kind: 'table' }>): void {
  const widths = columnWidths(
    (text, bold) => doc.font(bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(SMALL).widthOfString(safe(text)),
    b.head,
    b.rows,
    contentWidth(doc),
  );
  ensureSpace(doc, rowHeight(doc, b.head, widths, true) + (b.rows[0] ? rowHeight(doc, b.rows[0], widths, false) : 0));
  tableRow(doc, b.head, widths, true);
  for (const row of b.rows) {
    if (doc.y + rowHeight(doc, row, widths, false) > bottom(doc)) {
      doc.addPage();
      tableRow(doc, b.head, widths, true);
    }
    tableRow(doc, row, widths, false);
  }
  doc.moveDown(0.6);
}

function footers(doc: Doc, footer: string): void {
  const range = doc.bufferedPageRange();
  for (let i = range.start; i < range.start + range.count; i += 1) {
    doc.switchToPage(i);
    const saved = doc.page.margins.bottom;
    doc.page.margins.bottom = 0;
    doc
      .font('Helvetica')
      .fontSize(8)
      .fillColor(MUTED)
      .text(`${safe(footer)} · page ${i + 1} of ${range.count}`, MARGIN, doc.page.height - 32, { width: contentWidth(doc), align: 'center', lineBreak: false });
    doc.page.margins.bottom = saved;
  }
}

/** The report's blocks as an A4 PDF in the built-in Helvetica, so no font files or browser are needed. */
export function renderPdf(blocks: readonly Block[], opts: PdfOptions): Promise<Buffer> {
  const doc = new PDFDocument({
    size: 'A4',
    margins: { top: MARGIN, bottom: MARGIN, left: MARGIN, right: MARGIN },
    bufferPages: true,
    info: { Title: safe(opts.title), Creator: 'secagent', CreationDate: opts.createdAt },
  });
  const chunks: Buffer[] = [];
  const done = new Promise<Buffer>((resolve, reject) => {
    doc.on('data', (c: Buffer) => chunks.push(c));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
  });
  for (const b of blocks) {
    switch (b.kind) {
      case 'title':
        title(doc, b);
        break;
      case 'verdict':
        verdict(doc, b);
        break;
      case 'heading':
        heading(doc, b);
        break;
      case 'paragraph':
        paragraph(doc, b);
        break;
      case 'fields':
        fields(doc, b);
        break;
      case 'list':
        bulleted(doc, b.items);
        break;
      case 'table':
        table(doc, b);
        break;
    }
  }
  footers(doc, opts.footer);
  doc.end();
  return done;
}
