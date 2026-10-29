import { describe, expect, it } from 'vitest';
import { fetchSource, htmlToText, sourceProblem } from '../../src/kb/sources.js';
import { loadKnowledge } from '../../src/kb/store.js';
import { approveLesson, pendingLessons, rejectLesson, writeLesson } from '../../src/kb/write.js';
import { makeProject } from '../helpers/project.js';

const NOW = () => new Date('2026-10-28T10:00:00.000Z');
const HOSTS = new Set(['nginx.org', 'owasp.org']);
const PUBLIC = async () => ['93.184.216.34'];
const PAGE = '<html><head><script>ignore()</script></head><body><p>Sets the size of the buffer used for reading the first part of the response received from the proxied server.</p></body></html>';
const URL1 = 'https://nginx.org/en/docs/http/ngx_http_proxy_module.html';

function fakeFetch(routes: Record<string, { status: number; body?: string; location?: string; type?: string }>): typeof fetch {
  return (async (input: string | URL) => {
    const r = routes[String(input)];
    if (!r) return new Response('nope', { status: 404 });
    const headers: Record<string, string> = { 'content-type': r.type ?? 'text/html; charset=utf-8' };
    if (r.location) headers.location = r.location;
    return new Response(r.body ?? '', { status: r.status, headers });
  }) as typeof fetch;
}

describe('learning loop', () => {
  it('allows only https pages on allowlisted hosts', () => {
    expect(sourceProblem(URL1, HOSTS)).toBeUndefined();
    expect(sourceProblem('http://nginx.org/x', HOSTS)).toMatch(/https/);
    expect(sourceProblem('https://evil.example/x', HOSTS)).toMatch(/allowlist/);
    expect(sourceProblem('https://nginx.org:8443/x', HOSTS)).toMatch(/port/);
    expect(htmlToText(PAGE)).toBe('Sets the size of the buffer used for reading the first part of the response received from the proxied server.');
  });

  it('refuses a private address and a redirect off the allowlist', async () => {
    const dir = await makeProject();
    await expect(fetchSource(dir, URL1, { now: NOW, hosts: HOSTS, resolve: async () => ['10.0.0.1'], fetchImpl: fakeFetch({}) })).rejects.toThrow(/private/);
    const redirect = fakeFetch({ [URL1]: { status: 302, location: 'https://evil.example/' } });
    await expect(fetchSource(dir, URL1, { now: NOW, hosts: HOSTS, resolve: PUBLIC, fetchImpl: redirect })).rejects.toThrow(/redirected.*allowlist/);
  });

  it('saves a pending lesson only with an exact quote from a fetched page, and a person approves or rejects it', async () => {
    const dir = await makeProject();
    const draft = {
      id: 'proxy-buffer-login',
      title: 'Login responses need a bigger proxy buffer',
      body: 'Our login response sets four cookies; keep proxy_buffer_size at 16k or nginx returns 502 on sign-in.',
      tags: ['nginx'],
      source_url: URL1,
      quote: 'Sets the size of the buffer used for reading the first part of the response',
    };
    await expect(writeLesson(dir, draft, NOW())).rejects.toThrow(/fetch_source first/);
    await fetchSource(dir, URL1, { now: NOW, hosts: HOSTS, resolve: PUBLIC, fetchImpl: fakeFetch({ [URL1]: { status: 200, body: PAGE } }) });
    await expect(writeLesson(dir, { ...draft, quote: 'This sentence is not anywhere on that page at all.' }, NOW())).rejects.toThrow(/does not appear/);
    await expect(writeLesson(dir, { ...draft, source_url: 'https://evil.example/x' }, NOW())).rejects.toThrow(/allowlist/);

    const lesson = await writeLesson(dir, draft, NOW());
    expect(lesson).toMatchObject({ review: 'pending', added_by: 'learn-2026-10-28', layer: 'project' });
    await expect(writeLesson(dir, draft, NOW())).rejects.toThrow(/already exists/);
    expect((await pendingLessons(dir)).map((l) => l.id)).toEqual(['proxy-buffer-login']);

    const approved = await approveLesson(dir, 'proxy-buffer-login', 'Priya', NOW());
    expect(approved).toMatchObject({ review: 'approved', reviewed_by: 'Priya', reviewed_at: '2026-10-28' });
    expect((await loadKnowledge(dir, [])).lessons.find((l) => l.id === 'proxy-buffer-login')?.review).toBe('approved');
    await expect(rejectLesson(dir, 'proxy-buffer-login')).rejects.toThrow(/approved/);

    await writeLesson(dir, { ...draft, id: 'second-one' }, NOW());
    await rejectLesson(dir, 'second-one');
    expect(await pendingLessons(dir)).toEqual([]);
    await expect(approveLesson(dir, '../../project', 'x', NOW())).rejects.toThrow(/not a lesson id/);
  });
});
