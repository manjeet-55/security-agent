import { describe, expect, it } from 'vitest';
import {
  nginxDirectiveValues,
  parseAptPolicy,
  parseAutoUpgrades,
  parseListening,
  parseOsRelease,
  parsePackages,
  parseReboot,
  parseSshdT,
} from '../../src/host/parse.js';

describe('parsers', () => {
  it('reads os-release with quoted values', () => {
    expect(parseOsRelease('ID=ubuntu\nVERSION_ID="24.04"\nVERSION_CODENAME=noble\nPRETTY_NAME="Ubuntu 24.04.3 LTS"\n')).toEqual({
      id: 'ubuntu',
      version_id: '24.04',
      codename: 'noble',
      pretty_name: 'Ubuntu 24.04.3 LTS',
    });
  });

  it('keeps installed packages only, splitting arch and defaulting source', () => {
    const text = 'ii \tlibssl3t64:amd64\t3.0.13-0ubuntu3.16\topenssl\t3.0.13-0ubuntu3.16\nrc \told\t1.0\told\t1.0\nii \tbash\t5.2-1\t\t\n';
    expect(parsePackages(text)).toEqual([
      { name: 'libssl3t64', arch: 'amd64', version: '3.0.13-0ubuntu3.16', source: 'openssl', source_version: '3.0.13-0ubuntu3.16' },
      { name: 'bash', version: '5.2-1', source: 'bash', source_version: '5.2-1' },
    ]);
  });

  it('reads the installed version origins from apt-cache policy', () => {
    const text = [
      'nginx:',
      '  Installed: 1.30.6-1~noble',
      '  Candidate: 1.30.6-1~noble',
      '  Version table:',
      ' *** 1.30.6-1~noble 500',
      '        500 http://nginx.org/packages/ubuntu noble/nginx amd64 Packages',
      '        100 /var/lib/dpkg/status',
      '     1.24.0-2ubuntu7.19 500',
      '        500 http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages',
      'libssl3t64:',
      '  Installed: 3.0.13-0ubuntu3.16',
      ' *** 3.0.13-0ubuntu3.16 500',
      '        500 http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages',
    ].join('\n');
    expect(parseAptPolicy(text)).toEqual({
      nginx: {
        installed: '1.30.6-1~noble',
        sources: ['http://nginx.org/packages/ubuntu noble/nginx amd64 Packages', '/var/lib/dpkg/status'],
        available: [{ version: '1.24.0-2ubuntu7.19', sources: ['http://archive.ubuntu.com/ubuntu noble-updates/main amd64 Packages'] }],
      },
      libssl3t64: {
        installed: '3.0.13-0ubuntu3.16',
        sources: ['http://security.ubuntu.com/ubuntu noble-security/main amd64 Packages'],
        available: [],
      },
    });
  });

  it('parses sshd -T keys in lowercase and joins repeated keys', () => {
    expect(parseSshdT('PasswordAuthentication yes\nhostkey /a\nhostkey /b\n')).toEqual({ passwordauthentication: 'yes', hostkey: '/a /b' });
  });

  it('parses ss -tlnpH including IPv6, wildcard and interface-scoped addresses', () => {
    const text = [
      'LISTEN 0      511    0.0.0.0:80   0.0.0.0:* users:(("nginx",pid=1,fd=6))',
      'LISTEN 0      128       [::]:22      [::]:* users:(("sshd",pid=2,fd=4))',
      'LISTEN 0      4096   127.0.0.53%lo:53 0.0.0.0:*',
      'LISTEN 0      100          *:5432       *:*',
    ].join('\n');
    expect(parseListening(text)).toEqual([
      { address: '0.0.0.0', port: 80, process: 'nginx' },
      { address: '::', port: 22, process: 'sshd' },
      { address: '127.0.0.53', port: 53 },
      { address: '*', port: 5432 },
    ]);
  });

  it('reads unattended-upgrades state and reboot state', () => {
    expect(parseAutoUpgrades('APT::Periodic::Unattended-Upgrade "1";\nii unattended-upgrades\n')).toEqual({ enabled: true, installed: true });
    expect(parseAutoUpgrades('')).toEqual({ enabled: false, installed: false });
    expect(parseReboot('required\nlinux-image-6.8.0-1\nlibc6\n')).toEqual({ required: true, packages: ['linux-image-6.8.0-1', 'libc6'] });
    expect(parseReboot('not-required\n')).toEqual({ required: false, packages: [] });
  });

  it('finds nginx directive values and ignores comments', () => {
    const conf = '\t# server_tokens off;\n\tserver_tokens on;\nserver { listen 443 ssl; ssl_protocols TLSv1.2 TLSv1.3; }\n';
    expect(nginxDirectiveValues(conf, 'server_tokens')).toEqual(['on']);
    expect(nginxDirectiveValues(conf, 'ssl_protocols')).toEqual(['TLSv1.2 TLSv1.3']);
    expect(nginxDirectiveValues(conf, 'gzip')).toEqual([]);
  });
});
