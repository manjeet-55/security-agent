import type { Severity } from '../types.js';
import type { Block, Span, Tone } from './model.js';

const TONE: Record<Tone, string> = { red: '#b42318', yellow: '#b54708', green: '#067647' };
const SEVERITY: Record<Severity, string> = { critical: '#7a271a', high: '#b42318', medium: '#b54708', low: '#175cd3', info: '#475467' };

function esc(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** Only http(s) links become anchors; anything else is shown as text. */
function safeHref(href: string): string | undefined {
  return /^https?:\/\//i.test(href) ? esc(href) : undefined;
}

function span(s: Span): string {
  const text = esc(s.text).replace(/\n/g, '<br>');
  if (s.code) return `<code>${text}</code>`;
  const href = s.href ? safeHref(s.href) : undefined;
  if (href) return `<a href="${href}" rel="noopener noreferrer">${text}</a>`;
  return s.bold ? `<strong>${text}</strong>` : text;
}

const spans = (xs: readonly Span[]) => xs.map(span).join('');

function block(b: Block): string {
  switch (b.kind) {
    case 'title':
      return `<header><h1>${esc(b.text)}</h1><p class="meta">${esc(b.meta)}</p></header>`;
    case 'verdict':
      return `<p class="verdict" style="background:${TONE[b.tone]}">${esc(b.text)}</p>`;
    case 'heading':
      if (b.level === 2) return `<h2>${esc(b.text)}</h2>`;
      return `<h3>${b.severity ? `<span class="sev" style="background:${SEVERITY[b.severity]}">${b.severity.toUpperCase()}</span> ` : ''}${esc(b.text)}</h3>`;
    case 'paragraph':
      return `<p>${spans(b.spans)}</p>`;
    case 'fields':
      return `<ul class="fields">${b.items.map((i) => `<li><strong>${esc(i.label)}:</strong> ${spans(i.spans)}</li>`).join('')}</ul>`;
    case 'list':
      return `<ul>${b.items.map((i) => `<li>${spans(i)}</li>`).join('')}</ul>`;
    case 'table':
      return `<table><thead><tr>${b.head.map((h) => `<th>${esc(h)}</th>`).join('')}</tr></thead><tbody>${b.rows
        .map((r) => `<tr>${r.map((c) => `<td>${esc(c).replace(/\n/g, '<br>')}</td>`).join('')}</tr>`)
        .join('')}</tbody></table>`;
  }
}

const CSS = `
:root{--ink:#101828;--muted:#475467;--rule:#d0d5dd;--head:#f2f4f7;--link:#175cd3;--bg:#fff}
@media (prefers-color-scheme:dark){:root{--ink:#e4e7ec;--muted:#98a2b3;--rule:#344054;--head:#1d2939;--link:#84adff;--bg:#101828}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--ink);font:15px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
main{max-width:920px;margin:0 auto;padding:32px 16px 64px}h1{font-size:28px;margin:0 0 4px}.meta{color:var(--muted);margin:0 0 20px}
.verdict{color:#fff;font-weight:700;font-size:17px;padding:12px 16px;border-radius:6px}
h2{font-size:20px;margin:32px 0 10px;padding-bottom:6px;border-bottom:1px solid var(--rule)}h3{font-size:16px;margin:22px 0 6px}
.sev{display:inline-block;color:#fff;font-size:11px;font-weight:700;padding:2px 7px;border-radius:4px;vertical-align:2px}
ul{padding-left:20px}li{margin:3px 0}a{color:var(--link);word-break:break-word}code{font:13px ui-monospace,Menlo,Consolas,monospace;word-break:break-all}
.fields{list-style:none;padding-left:0}
table{border-collapse:collapse;width:100%;font-size:14px;display:block;overflow-x:auto}th,td{text-align:left;vertical-align:top;padding:7px 9px;border-bottom:1px solid var(--rule)}th{background:var(--head)}
@media print{.verdict,.sev{-webkit-print-color-adjust:exact;print-color-adjust:exact}main{max-width:none}}
`;

/** The report's blocks as one self-contained HTML page: no scripts, no external files, every text escaped. */
export function renderHtml(blocks: readonly Block[], opts: { title: string }): string {
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>${esc(opts.title)}</title><style>${CSS}</style></head>
<body><main>
${blocks.map(block).join('\n')}
</main></body></html>
`;
}
