import { describe, expect, it } from 'vitest';
import { aptListsEmpty, classifyOrigin } from '../../src/host/origin.js';

const o = (...sources: string[]) => ({ installed: '1', sources, available: [] });

describe('classifyOrigin', () => {
  it('treats an outdated distro package (installed version left the index) as distro', () => {
    const outdated = {
      installed: '1.0-1ubuntu1',
      sources: ['/var/lib/dpkg/status'],
      available: [{ version: '1.0-1ubuntu2', sources: ['http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages'] }],
    };
    expect(classifyOrigin(outdated, 'noble').kind).toBe('distro');
  });

  it('treats a vendor build newer than the distro version as local', () => {
    const vendor = {
      installed: '1.30.6-1~trixie',
      sources: ['/var/lib/dpkg/status'],
      available: [{ version: '1.26.3-3', sources: ['http://deb.debian.org/debian trixie/main amd64 Packages'] }],
    };
    expect(classifyOrigin(vendor, 'trixie').kind).toBe('local');
  });

  it.each([
    [['http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages'], 'distro'],
    [['http://mirrors.example.net/ubuntu noble-updates/universe amd64 Packages'], 'distro'],
    [['http://deb.debian.org/debian-security bookworm-security/main amd64 Packages'], 'distro'],
    [['http://nginx.org/packages/ubuntu noble/nginx amd64 Packages', '/var/lib/dpkg/status'], 'third_party'],
    [['https://download.docker.com/linux/ubuntu noble/stable amd64 Packages'], 'third_party'],
    [['https://ppa.launchpadcontent.net/foo/bar/ubuntu noble/main amd64 Packages'], 'third_party'],
    [['/var/lib/dpkg/status'], 'local'],
  ])('%j → %s', (sources, kind) => {
    expect(classifyOrigin(o(...sources), 'noble').kind === kind || classifyOrigin(o(...sources), 'bookworm').kind === kind).toBe(true);
  });

  it('is unknown without apt-cache data', () => {
    expect(classifyOrigin(undefined, 'noble')).toEqual({ kind: 'unknown' });
  });

  it('detects emptied apt lists', () => {
    expect(aptListsEmpty({ a: o('/var/lib/dpkg/status'), b: o('/var/lib/dpkg/status') })).toBe(true);
    expect(aptListsEmpty({ a: o('/var/lib/dpkg/status'), b: o('http://deb.debian.org/debian trixie/main amd64 Packages') })).toBe(false);
    const onlyNewerOffered = { installed: '1', sources: ['/var/lib/dpkg/status'], available: [{ version: '2', sources: ['http://deb.debian.org/debian trixie/main amd64 Packages'] }] };
    expect(aptListsEmpty({ a: onlyNewerOffered })).toBe(false);
  });
});
