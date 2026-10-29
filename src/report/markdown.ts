import type { Block, Span, Tone } from './model.js';

const TONE_MARK: Record<Tone, string> = { red: '🔴', yellow: '🟡', green: '🟢' };

/** Plain text that shows as written: Markdown emphasis, code and HTML characters are escaped. */
function escapeText(text: string): string {
  return text.replace(/[\\`*_]/g, '\\$&').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function codeSpan(text: string): string {
  return text.includes('`') ? `\`\` ${text} \`\`` : `\`${text}\``;
}

function renderSpan(s: Span): string {
  if (s.code) return codeSpan(s.text);
  const text = escapeText(s.text);
  if (s.href) return `[${text}](${s.href})`;
  return s.bold ? `**${text}**` : text;
}

/** Spans as one Markdown line; a newline inside becomes a hard line break, indented to stay inside a list item. */
function renderSpans(spans: readonly Span[], indent = ''): string {
  return spans.map(renderSpan).join('').split('\n').join(`  \n${indent}`);
}

function tableCell(text: string): string {
  return escapeText(text).replace(/\|/g, '\\|').replace(/\n/g, '<br>');
}

function renderBlock(b: Block): string {
  switch (b.kind) {
    case 'title':
      return `# ${escapeText(b.text)}\n\n${escapeText(b.meta)}`;
    case 'verdict':
      return `> ${TONE_MARK[b.tone]} **${escapeText(b.text)}**`;
    case 'heading':
      return `${'#'.repeat(b.level)} ${escapeText(b.text)}`;
    case 'paragraph':
      return renderSpans(b.spans);
    case 'fields':
      return b.items.map((i) => `- **${escapeText(i.label)}:** ${renderSpans(i.spans, '  ')}`).join('\n');
    case 'list':
      return b.items.map((spans) => `- ${renderSpans(spans, '  ')}`).join('\n');
    case 'table':
      return [
        `| ${b.head.map(tableCell).join(' | ')} |`,
        `| ${b.head.map(() => '---').join(' | ')} |`,
        ...b.rows.map((row) => `| ${row.map(tableCell).join(' | ')} |`),
      ].join('\n');
  }
}

export function renderMarkdown(blocks: readonly Block[]): string {
  return `${blocks.map(renderBlock).join('\n\n')}\n`;
}
