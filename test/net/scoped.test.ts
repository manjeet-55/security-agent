import { describe, expect, it } from 'vitest';
import { NetError } from '../../src/net/errors.js';
import { ScopedNet, withRetry } from '../../src/net/scoped.js';
import { validateProject } from '../../src/project/schema.js';
import { Scope, ScopeError } from '../../src/project/scope.js';
import { startHttp } from '../helpers/servers.js';

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
