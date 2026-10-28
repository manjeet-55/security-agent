import { describe, expect, it } from 'vitest';
import { validateProject } from '../../src/project/schema.js';
import { NetError } from '../../src/net/errors.js';
import { Scope, ScopeError } from '../../src/project/scope.js';

function scopeFor(targets: unknown[], hosts: unknown[] = []): Scope {
  return new Scope(validateProject({ version: 1, name: 't', targets, hosts }));
}

describe('Scope', () => {
  it('rejects hostnames that are not listed', async () => {
    const scope = scopeFor([{ id: 'app', url: 'https://203.0.113.10', type: 'web', env: 'prod' }]);
    await expect(scope.assertHostnameAllowed('198.51.100.7')).rejects.toThrow(/not in project.yaml/);
  });

  it('allows listed target hostnames and host addresses', async () => {
    const scope = scopeFor(
      [{ id: 'app', url: 'https://203.0.113.10:8443', type: 'web', env: 'prod' }],
      [{ name: 'web-1', address: '203.0.113.11', env: 'prod' }],
    );
    expect(await scope.assertHostnameAllowed('203.0.113.10')).toEqual(['203.0.113.10']);
    expect(await scope.assertUrlAllowed('http://203.0.113.10/')).toEqual(['203.0.113.10']);
    expect(await scope.assertHostnameAllowed('203.0.113.11')).toEqual(['203.0.113.11']);
  });

  it('treats a private IP literal as explicitly listed', async () => {
    const scope = scopeFor([{ id: 'lab', url: 'https://172.31.250.10', type: 'web', env: 'lab' }]);
    expect(await scope.assertHostnameAllowed('172.31.250.10')).toEqual(['172.31.250.10']);
  });

  it('blocks a hostname that resolves to a private address unless allow_private is set', async () => {
    const blocked = scopeFor([{ id: 'local', url: 'http://localhost:3000', type: 'web', env: 'dev' }]);
    await expect(blocked.assertHostnameAllowed('LOCALHOST')).rejects.toThrow(/allow_private/);
    const allowed = scopeFor([{ id: 'local', url: 'http://localhost:3000', type: 'web', env: 'dev', allow_private: true }]);
    expect(await allowed.assertHostnameAllowed('localhost')).toContain('127.0.0.1');
  });

  it('rejects non-http URLs', async () => {
    const scope = scopeFor([{ id: 'app', url: 'https://203.0.113.10', type: 'web', env: 'prod' }]);
    await expect(scope.assertUrlAllowed('ftp://203.0.113.10/')).rejects.toBeInstanceOf(ScopeError);
  });

  it('looks up targets and hosts by id with a helpful error', () => {
    const scope = scopeFor([{ id: 'app', url: 'https://203.0.113.10', type: 'web', env: 'prod' }]);
    expect(scope.target('app').url).toBe('https://203.0.113.10');
    expect(() => scope.target('nope')).toThrow(/Targets in project.yaml: app/);
    expect(() => scope.host('nope')).toThrow(ScopeError);
  });

  it('does not cache transient DNS failures', async () => {
    let calls = 0;
    const resolve = async (): Promise<string[]> => {
      calls += 1;
      if (calls === 1) throw new NetError('DNS_FAILED', 'flaky');
      return ['203.0.113.5'];
    };
    const project = validateProject({ version: 1, name: 't', targets: [{ id: 'app', url: 'https://app.example.com', type: 'web', env: 'prod' }], hosts: [] });
    const scope = new Scope(project, resolve);
    await expect(scope.assertHostnameAllowed('app.example.com')).rejects.toBeInstanceOf(NetError);
    expect(await scope.assertHostnameAllowed('app.example.com')).toEqual(['203.0.113.5']);
    expect(calls).toBe(2);
  });

  it('keeps private-address refusals cached', async () => {
    let calls = 0;
    const resolve = async (): Promise<string[]> => {
      calls += 1;
      return ['10.0.0.5'];
    };
    const project = validateProject({ version: 1, name: 't', targets: [{ id: 'int', url: 'https://internal.example.com', type: 'web', env: 'prod' }], hosts: [] });
    const scope = new Scope(project, resolve);
    await expect(scope.assertHostnameAllowed('internal.example.com')).rejects.toBeInstanceOf(ScopeError);
    await expect(scope.assertHostnameAllowed('internal.example.com')).rejects.toBeInstanceOf(ScopeError);
    expect(calls).toBe(1);
  });
});
