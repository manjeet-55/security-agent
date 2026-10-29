import { describe, expect, it } from 'vitest';
import { renderHtml } from '../../src/report/html.js';
import { buildReport } from '../../src/report/model.js';
import { fixtureInstances, fixtureProject, fixtureRecord } from './fixture.js';

describe('renderHtml', () => {
  it('renders a whole report as one page with no scripts', () => {
    const html = renderHtml(buildReport({ project: fixtureProject(), record: fixtureRecord(), instances: fixtureInstances() }), { title: 'Security report: shop' });
    for (const h of ['<h1>Security report: shop</h1>', '<h2>Findings</h2>', 'class="verdict"', '<table>']) expect(html).toContain(h);
    expect(html).not.toMatch(/<script/i);
    expect(html).toContain("default-src 'none'");
  });

  it('escapes hostile text and only links http(s) addresses', () => {
    const html = renderHtml(
      [
        { kind: 'paragraph', spans: [{ text: '<script>alert(1)</script> "x" & \'y\'' }] },
        { kind: 'paragraph', spans: [{ text: 'click', href: 'javascript:alert(1)' }, { text: 'ok', href: 'https://example.com/?a=1&b="2"' }] },
        { kind: 'table', head: ['<b>h</b>'], rows: [['<img src=x onerror=alert(1)>']] },
      ],
      { title: '</title><script>' },
    );
    expect(html).not.toContain('<script>alert');
    expect(html).not.toContain('<img src=x');
    expect(html).not.toContain('javascript:');
    expect(html).toContain('href="https://example.com/?a=1&amp;b=&quot;2&quot;"');
    expect(html).toContain('&lt;script&gt;alert(1)&lt;/script&gt;');
  });
});
