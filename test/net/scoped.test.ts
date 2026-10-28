import { describe, expect, it } from 'vitest';
import { pinnedLookup } from '../../src/net/ip.js';
import { NetError } from '../../src/net/errors.js';
import { ScopedNet, withRetry } from '../../src/net/scoped.js';
import { validateProject } from '../../src/project/schema.js';
import { Scope, ScopeError } from '../../src/project/scope.js';
import { startHttp, startHttps, startTls, useServers } from '../helpers/servers.js';

describe('ScopedNet', () => {
  it('refuses unlisted hosts before opening a connection, and allows listed ones', async () => {
    const s = await startHttp((_req, res) => res.end('ok'));
    try {
      const project = validateProject({
        version: 1,
        name: 't',
        targets: [{ id: 'local', url: `http://127.0.0.1:${s.port}`, type: 'web', env: 'test' }],
      });
      const net = new ScopedNet(new Scope(project), 4);
      await expect(net.http('http://127.0.0.2/')).rejects.toBeInstanceOf(ScopeError);
      await expect(net.tcp('127.0.0.2', 80)).rejects.toBeInstanceOf(ScopeError);
      expect((await net.http(`${s.url}/`)).status).toBe(200);
      expect(await net.tcp('127.0.0.1', s.port)).toBe('open');
    } finally {
      await s.close();
    }
  });
});

describe('withRetry', () => {
  it('retries once on a timeout', async () => {
    let calls = 0;
    const result = await withRetry(async () => {
      calls += 1;
      if (calls === 1) throw new NetError('TIMEOUT', 'slow');
      return 'ok';
    });
    expect(result).toBe('ok');
    expect(calls).toBe(2);
  });

  it('does not retry other errors', async () => {
    let calls = 0;
    await expect(
      withRetry(async () => {
        calls += 1;
        throw new NetError('ECONNREFUSED', 'no');
      }),
    ).rejects.toMatchObject({ code: 'ECONNREFUSED' });
    expect(calls).toBe(1);
  });
});

describe('pinnedLookup', () => {
  const call = (lookup: ReturnType<typeof pinnedLookup>, options: Parameters<ReturnType<typeof pinnedLookup>>[1]) =>
    new Promise<{ err: NodeJS.ErrnoException | null; address: unknown; family?: number }>((resolve) => {
      lookup('example.test', options, ((err: NodeJS.ErrnoException | null, address: unknown, family?: number) =>
        resolve({ err, address, family })) as never);
    });

  it('answers only with the pinned addresses, honouring all', async () => {
    const lookup = pinnedLookup(['127.0.0.2', '::1']);
    expect((await call(lookup, { all: true })).address).toEqual([
      { address: '127.0.0.2', family: 4 },
      { address: '::1', family: 6 },
    ]);
    expect((await call(lookup, { all: true, family: 6 })).address).toEqual([{ address: '::1', family: 6 }]);
    expect((await call(lookup, { all: true, family: 'IPv4' })).address).toEqual([{ address: '127.0.0.2', family: 4 }]);
    const single = await call(lookup, { family: 4 });
    expect(single.address).toBe('127.0.0.2');
    expect(single.family).toBe(4);
    expect((await call(lookup, {})).address).toBe('127.0.0.2');
  });

  it('fails with ENOTFOUND when no pinned address matches', async () => {
    const lookup = pinnedLookup(['127.0.0.2']);
    expect((await call(lookup, { family: 6 })).err?.code).toBe('ENOTFOUND');
    expect((await call(lookup, { all: true, family: 6 })).err?.code).toBe('ENOTFOUND');
    expect((await call(pinnedLookup([]), {})).err?.code).toBe('ENOTFOUND');
  });
});

describe.runIf(process.platform === 'linux')('ScopedNet address pinning', () => {
  const track = useServers();
  const setup = async () => {
    const web = await track(startHttp((_req, res) => res.end('ok'), '127.0.0.2'));
    const secure = await track(startHttps((_req, res) => res.end('ok'), {}, '127.0.0.2'));
    const bare = await track(startTls({}, '127.0.0.2'));
    const project = validateProject({
      version: 1,
      name: 't',
      targets: [
        { id: 'web', url: `http://localhost:${web.port}`, type: 'web', env: 'test', allow_private: true },
        { id: 'secure', url: `https://localhost:${secure.port}`, type: 'web', env: 'test', allow_private: true },
      ],
    });
    return { web, secure, bare, net: new ScopedNet(new Scope(project, async () => ['127.0.0.2']), 4) };
  };

  it('connects to the validated address, not to whatever the system resolves', async () => {
    const { web, bare, net } = await setup();
    const res = await net.http(`http://localhost:${web.port}/`);
    expect(res.status).toBe(200);
    expect(res.remoteAddress).toBe('127.0.0.2');
    expect((await net.tls('localhost', bare.port)).protocol).not.toBeNull();
    expect(await net.tcp('localhost', web.port)).toBe('open');
  });

  it('pins https requests too', async () => {
    const { secure, net } = await setup();
    const res = await net.http(`https://localhost:${secure.port}/`);
    expect(res.remoteAddress).toBe('127.0.0.2');
  });

  it('refuses a Host header override before any network activity', async () => {
    const { web, net } = await setup();
    await expect(net.http(`http://localhost:${web.port}/`, { headers: { Host: 'other.example.net' } })).rejects.toBeInstanceOf(ScopeError);
  });

  it('refuses an unlisted SNI name', async () => {
    const { bare, net } = await setup();
    await expect(net.tls('localhost', bare.port, { servername: 'evil.example.org' })).rejects.toBeInstanceOf(ScopeError);
  });
});
