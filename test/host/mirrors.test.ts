import { describe, expect, it } from 'vitest';
import { classifyOrigin } from '../../src/host/origin.js';
import { validateProject } from '../../src/project/schema.js';

const origin = (source: string) => ({ installed: '1.0', sources: [source], available: [] });
const MIRROR = 'http://mirror.example.net/ubuntu noble-security/main amd64 Packages';

describe('distro_mirrors', () => {
  it('a listed mirror counts as the distro, only for distro suites and components; an unlisted one stays unknown', () => {
    expect(classifyOrigin(origin(MIRROR), 'noble').kind).toBe('unknown');
    expect(classifyOrigin(origin(MIRROR), 'noble', ['mirror.example.net']).kind).toBe('distro');
    expect(classifyOrigin(origin('http://mirror.example.net/nginx noble/nginx amd64 Packages'), 'noble', ['mirror.example.net']).kind).toBe('third_party');
    expect(classifyOrigin(origin('http://other.example.net/ubuntu noble/main amd64 Packages'), 'noble', ['mirror.example.net']).kind).toBe('unknown');
    expect(classifyOrigin(origin('http://mirror.example.net.evil.example/ubuntu noble/main amd64 Packages'), 'noble', ['mirror.example.net']).kind).toBe('unknown');
  });

  it('project.yaml takes exact host names only', () => {
    const base = { version: 1, name: 'x', hosts: [{ name: 'web-1', address: '203.0.113.10', env: 'prod', distro_mirrors: ['mirror.example.net'] }] };
    expect(validateProject(base).hosts[0]?.distro_mirrors).toEqual(['mirror.example.net']);
    for (const bad of ['*.example.net', 'http://mirror.example.net', 'mirror.example.net/ubuntu']) {
      expect(() => validateProject({ ...base, hosts: [{ ...base.hosts[0], distro_mirrors: [bad] }] })).toThrow();
    }
  });
});
