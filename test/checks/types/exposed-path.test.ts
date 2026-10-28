import { readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { exposedPathCheck, exposedPathParams, isExposed, scriptSources } from '../../../src/checks/types/exposed-path.js';
import { fakeObs, makeCtx, targetSubject } from '../../helpers/ctx.js';

const ENV_SIGNATURE = /^[A-Z][A-Z0-9_]*\s*=/m;

describe('isExposed', () => {
  const baseline = fakeObs({ status: 200, bodySnippet: '<html>app shell</html>' });
  it('ignores the SPA fallback page', () => {
    expect(isExposed(fakeObs({ status: 200, bodySnippet: '<html>app shell</html>' }), baseline, ENV_SIGNATURE)).toBe(false);
  });
  it('requires a 200', () => {
    expect(isExposed(fakeObs({ status: 404, bodySnippet: 'DB_PASSWORD=x' }), baseline, ENV_SIGNATURE)).toBe(false);
  });
  it('requires the content signature', () => {
    expect(isExposed(fakeObs({ status: 200, bodySnippet: 'hello' }), baseline, ENV_SIGNATURE)).toBe(false);
  });
  it('flags a real .env file', () => {
    expect(isExposed(fakeObs({ status: 200, bodySnippet: 'DB_PASSWORD=x\n' }), baseline, ENV_SIGNATURE)).toBe(true);
  });
});

describe('scriptSources', () => {
  it('resolves relative script URLs and drops duplicates', () => {
    const html = '<script src="/main.js"></script><script type="module" src="chunk.js?v=1"></script><script src="/main.js"></script>';
    expect(scriptSources(html, 'https://app.example.com/a/')).toEqual([
      'https://app.example.com/main.js',
      'https://app.example.com/a/chunk.js?v=1',
    ]);
  });
});

describe('exposed_path check', () => {
  it('reports exposed files and source maps, skips SPA fallbacks, and stores no file contents', async () => {
    const pages: Record<string, { status: number; body: string }> = {
      '/': { status: 200, body: '<html><script src="/main.js"></script></html>' },
      '/.env': { status: 200, body: 'DB_PASSWORD=supersecret\n' },
      '/main.js.map': { status: 200, body: '{"version":3,"mappings":"AAAA"}' },
    };
    const { ctx, dir } = await makeCtx({
      http: async (url) => {
        const page = pages[new URL(url).pathname] ?? { status: 200, body: '<html>shell</html>' };
        return fakeObs({ url, status: page.status, bodySnippet: page.body });
      },
    });
    const params = exposedPathParams.parse({
      paths: [
        { path: '/.env', signature: '^[A-Z][A-Z0-9_]*\\s*=', severity: 'critical' },
        { path: '/.git/config', signature: '^\\[core\\]', severity: 'high' },
      ],
    });
    const out = await exposedPathCheck.run(ctx, targetSubject(ctx), params, {} as never);
    expect(out.outcome).toBe('fail');
    expect(out.severity).toBe('critical');
    expect(out.observed).toContain('/.env');
    expect(out.observed).toContain('/main.js.map');
    expect(out.observed).not.toContain('/.git/config');
    const evidence = readFileSync(path.join(dir, '.secagent', 'evidence', `${out.evidence_id}.json`), 'utf8');
    expect(evidence).not.toContain('supersecret');
  });

  describe('source maps with a late "mappings" key', () => {
    const rollupMap = `{"version":3,"file":"main.js","sources":["a.ts"],"sourcesContent":["${'x'.repeat(5000)}"],"names":[],"mappings":"AAAA"}`;
    const cases: Array<[string, string]> = [
      ['a Rollup-style map', rollupMap],
      ['a map with the XSSI prefix', `)]}'\n${rollupMap}`],
    ];
    it.each(cases)('detects %s truncated to the 4096-char snippet', async (_name, map) => {
      const { ctx } = await makeCtx({
        http: async (url) => {
          const pathname = new URL(url).pathname;
          if (pathname === '/') return fakeObs({ url, status: 200, bodySnippet: '<html><script src="/main.js"></script></html>' });
          if (pathname === '/main.js.map') return fakeObs({ url, status: 200, bodySnippet: map.slice(0, 4096) });
          return fakeObs({ url, status: 404, bodySnippet: 'nope' });
        },
      });
      const params = exposedPathParams.parse({ paths: [{ path: '/.env', signature: '^[A-Z][A-Z0-9_]*\\s*=', severity: 'critical' }] });
      const out = await exposedPathCheck.run(ctx, targetSubject(ctx), params, {} as never);
      expect(out.outcome).toBe('fail');
      expect(out.observed).toContain('/main.js.map');
    });
  });

  it('rejects an invalid signature regex', () => {
    expect(exposedPathParams.safeParse({ paths: [{ path: '/.env', signature: '([', severity: 'high' }] }).success).toBe(false);
  });
});
