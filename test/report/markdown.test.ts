import { describe, expect, it } from 'vitest';
import { renderMarkdown } from '../../src/report/markdown.js';
import { buildReport } from '../../src/report/model.js';
import { fixtureInstances, fixtureProject, fixtureRecord } from './fixture.js';

describe('renderMarkdown', () => {
  it('renders every block kind', () => {
    const md = renderMarkdown([
      { kind: 'title', text: 'Security report: shop', meta: 'Scanned today' },
      { kind: 'verdict', tone: 'red', text: 'Needs attention' },
      { kind: 'heading', level: 2, text: 'Findings' },
      { kind: 'heading', level: 3, text: 'Failed: Leak', severity: 'high' },
      { kind: 'paragraph', spans: [{ text: 'plain ' }, { text: 'bold', bold: true }, { text: ' and ' }, { text: 'a_b', code: true }] },
      { kind: 'fields', items: [{ label: 'How to fix', spans: [{ text: 'line one\nline two' }] }, { label: 'Learn more', spans: [{ text: 'docs', href: 'https://x.example/a' }] }] },
      { kind: 'list', items: [[{ text: 'first' }], [{ text: 'second' }]] },
      { kind: 'table', head: ['A', 'B'], rows: [['x | y', 'multi\nline']] },
    ]);
    expect(md).toBe(
      [
        '# Security report: shop',
        '',
        'Scanned today',
        '',
        '> 🔴 **Needs attention**',
        '',
        '## Findings',
        '',
        '### HIGH · Failed: Leak',
        '',
        'plain **bold** and `a_b`',
        '',
        '- **How to fix:** line one  ',
        '  line two',
        '- **Learn more:** [docs](https://x.example/a)',
        '',
        '- first',
        '- second',
        '',
        '| A | B |',
        '| --- | --- |',
        '| x \\| y | multi<br>line |',
        '',
      ].join('\n'),
    );
  });

  it('escapes Markdown in plain text so file names and observations show as written', () => {
    const md = renderMarkdown([{ kind: 'paragraph', spans: [{ text: 'src/my_file.ts *x* <script>' }] }]);
    expect(md).toBe('src/my\\_file.ts \\*x\\* &lt;script&gt;\n');
  });

  it('turns a whole report into Markdown with every section', () => {
    const md = renderMarkdown(buildReport({ project: fixtureProject(), record: fixtureRecord(), instances: fixtureInstances() }));
    for (const h of ['# Security report: shop', '## At a glance', '## Fix first', '## Findings', '### HIGH · Failed: code-leak title', '## Could not verify', '## Passed', '## About this scan']) {
      expect(md).toContain(h);
    }
    expect(md).toContain('| Code | 2 | 1 | 0 |');
  });
});
