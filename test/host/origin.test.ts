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
    [['http://archive.ubuntu.com/ubuntu noble/main amd64 Packages'], 'noble', 'distro'],
    [['http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages'], 'noble', 'distro'],
    [['http://archive.ubuntu.com/ubuntu noble-updates/universe amd64 Packages'], 'noble', 'distro'],
    [['http://ports.ubuntu.com/ubuntu-ports noble-security/main arm64 Packages'], 'noble', 'distro'],
    [['https://esm.ubuntu.com/apps/ubuntu noble-apps-security/main amd64 Packages'], 'noble', 'distro'],
    [['http://deb.debian.org/debian bookworm/main amd64 Packages'], 'bookworm', 'distro'],
    [['http://deb.debian.org/debian-security bookworm-security/main amd64 Packages'], 'bookworm', 'distro'],
    [['http://security.debian.org/debian-security bookworm-security/main amd64 Packages'], 'bookworm', 'distro'],
    [['http://nginx.org/packages/ubuntu noble/nginx amd64 Packages', '/var/lib/dpkg/status'], 'noble', 'third_party'],
    [['https://download.docker.com/linux/ubuntu noble/stable amd64 Packages'], 'noble', 'third_party'],
    [['https://ppa.launchpadcontent.net/foo/bar/ubuntu noble/main amd64 Packages'], 'noble', 'third_party'],
    [['/var/lib/dpkg/status'], 'noble', 'local'],
  ])('%j (%s) → %s', (sources, codename, kind) => {
    expect(classifyOrigin(o(...sources), codename).kind).toBe(kind);
  });

  // A distro-looking suite and component on a host that is not ubuntu.com/debian.org cannot be told from a vendor repo
  // that reuses the codename and `main`; a trailing /ubuntu or /debian in the path proves nothing.
  it.each([
    'https://packagecloud.io/acme/openssh/ubuntu noble/main amd64 Packages',
    'https://dl.cloudsmith.io/public/acme/openssh/deb/ubuntu noble/main amd64 Packages',
    'https://dlm.mariadb.com/repo/mariadb-server/11.4/repo/ubuntu noble/main amd64 Packages',
    'https://repo.zabbix.com/zabbix/7.0/ubuntu noble/main amd64 Packages',
    'https://ppa1.rabbitmq.com/rabbitmq/rabbitmq-erlang/deb/ubuntu noble/main amd64 Packages',
    'https://evil.example/ubuntu noble/main amd64 Packages',
    'http://mirrors.example.net/ubuntu noble-updates/universe amd64 Packages',
    'http://mirror.example.net/debian-security noble-security/main amd64 Packages',
    'https://packages.sury.org/php noble/main amd64 Packages',
    'https://packages.microsoft.com/ubuntu/22.04/prod noble/main amd64 Packages',
    'http://archive.ubuntu.com.evil.example/ubuntu noble/main amd64 Packages',
    'http://evil-ubuntu.com/ubuntu noble/main amd64 Packages',
    'http://archive.ubuntu.com@evil.example/ubuntu noble/main amd64 Packages',
  ])('%s is origin unknown, keeping the repository', (source) => {
    expect(classifyOrigin(o(source), 'noble')).toEqual({ kind: 'unknown', repo: source });
  });

  // The WHATWG URL parser treats a backslash as a slash, so new URL() reads the host of http://archive.ubuntu.com\.evil.attacker.example/ubuntu
  // as archive.ubuntu.com. apt does not read it that way, so the host is taken literally and anything odd is not a distro.
  it.each([
    String.raw`http://archive.ubuntu.com\.evil.attacker.example/ubuntu noble/main amd64 Packages`,
    String.raw`http://archive.ubuntu.com\@evil.example/ubuntu noble/main amd64 Packages`,
    String.raw`http://evil.example\@archive.ubuntu.com/ubuntu noble/main amd64 Packages`,
    'http://archive.ubuntu.com..evil.example/ubuntu noble/main amd64 Packages',
    'http://archive.ubuntu.com../ubuntu noble/main amd64 Packages',
    'http://archive.ubuntu.com?x=1/ubuntu noble/main amd64 Packages',
    'http://archive.ubuntu.com#frag/ubuntu noble/main amd64 Packages',
    'http://archive.ubuntu.com%2eevil.example/ubuntu noble/main amd64 Packages',
    'http://archive.ubuntu.com:abc/ubuntu noble/main amd64 Packages',
    'http://archive.ubuntu.com:80@evil.example/ubuntu noble/main amd64 Packages',
    'http://evil.example#@archive.ubuntu.com/ubuntu noble/main amd64 Packages',
    'http://evil.example?@archive.ubuntu.com/ubuntu noble/main amd64 Packages',
    'http://evil.example[x]@archive.ubuntu.com/ubuntu noble/main amd64 Packages',
    'http://[::1]/ubuntu noble/main amd64 Packages',
    'http:///ubuntu noble/main amd64 Packages',
    'archive.ubuntu.com/ubuntu noble/main amd64 Packages',
  ])('the odd host in %s is origin unknown, not distro', (source) => {
    expect(classifyOrigin(o(source), 'noble')).toEqual({ kind: 'unknown', repo: source });
  });

  it.each([
    'http://archive.ubuntu.com./ubuntu noble/main amd64 Packages',
    'http://Archive.Ubuntu.COM/ubuntu noble/main amd64 Packages',
    'HTTP://archive.ubuntu.com/ubuntu noble/main amd64 Packages',
    'http://archive.ubuntu.com:80/ubuntu noble/main amd64 Packages',
    'http://archive.ubuntu.com.:80/ubuntu noble/main amd64 Packages',
    'http://user:pw@archive.ubuntu.com/ubuntu noble/main amd64 Packages',
    'http://user:p%40ss@archive.ubuntu.com/ubuntu noble/main amd64 Packages',
    'http://user:p@ss@archive.ubuntu.com/ubuntu noble/main amd64 Packages',
    'http://user:******@archive.ubuntu.com/ubuntu noble/main amd64 Packages',
    'http://evil.example@archive.ubuntu.com/ubuntu noble/main amd64 Packages',
  ])('%s is a distro repository', (source) => {
    expect(classifyOrigin(o(source), 'noble')).toEqual({ kind: 'distro', repo: source });
  });

  it('a repository on a distro host with a non-distro suite is third-party, not distro', () => {
    expect(classifyOrigin(o('http://archive.ubuntu.com/ubuntu stable/main amd64 Packages'), 'noble').kind).toBe('third_party');
    expect(classifyOrigin(o('http://archive.ubuntu.com/ubuntu noble/partner amd64 Packages'), 'noble').kind).toBe('third_party');
  });

  it('a distro repository wins over an unknown one, and unknown wins over third-party', () => {
    const distro = 'http://archive.ubuntu.com/ubuntu noble/main amd64 Packages';
    const unknown = 'https://packagecloud.io/acme/openssh/ubuntu noble/main amd64 Packages';
    const vendor = 'http://nginx.org/packages/ubuntu noble/nginx amd64 Packages';
    expect(classifyOrigin(o(unknown, distro), 'noble').kind).toBe('distro');
    expect(classifyOrigin(o(vendor, unknown), 'noble')).toEqual({ kind: 'unknown', repo: unknown });
  });

  it('an outdated package whose newer version is offered only by an unidentified mirror is unknown, not local', () => {
    const mirror = 'https://packagecloud.io/acme/openssh/ubuntu noble/main amd64 Packages';
    const outdated = { installed: '1.0-1', sources: ['/var/lib/dpkg/status'], available: [{ version: '1.0-2', sources: [mirror] }] };
    expect(classifyOrigin(outdated, 'noble')).toEqual({ kind: 'unknown', repo: mirror });
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
