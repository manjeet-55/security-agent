import { cp, mkdir } from 'node:fs/promises';
import { existsSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanNoAi } from '../src/scan/no-ai.js';
import { tempDir } from './helpers/tmp.js';

const LAB = path.join(import.meta.dirname, '..', 'lab', 'project', '.secagent');
const ready = process.env.SECAGENT_LAB === '1' && existsSync(path.join(LAB, 'hosts', 'bad-host'));

// The lab images are nginx:1.30.6 (Debian 13): nginx from nginx.org, no sshd, no ss, no unattended-upgrades.
const EXPECTED: Array<[check: string, host: string, outcome: string]> = [
  ['host-ssh-password-auth', 'bad-host', 'pass'],
  ['host-ssh-root-login', 'bad-host', 'pass'],
  ['host-nginx-server-tokens', 'bad-host', 'fail'],
  ['host-nginx-server-tokens', 'good-host', 'pass'],
  ['host-nginx-ssl-protocols', 'bad-host', 'fail'],
  ['host-nginx-ssl-protocols', 'good-host', 'pass'],
  ['host-listening-databases', 'bad-host', 'unverifiable'],
  ['host-auto-upgrades', 'bad-host', 'fail'],
  ['host-package-third-party', 'bad-host', 'fail'],
  ['host-package-third-party', 'good-host', 'fail'],
  ['host-reboot-pending', 'good-host', 'pass'],
];

describe.runIf(ready)('lab host checks (run lab/collect-snapshots.sh first)', () => {
  it('evaluates the collected lab snapshots', async () => {
    const dir = await tempDir();
    await mkdir(path.join(dir, '.secagent'), { recursive: true });
    await cp(path.join(LAB, 'project.yaml'), path.join(dir, '.secagent', 'project.yaml'));
    await cp(path.join(LAB, 'hosts'), path.join(dir, '.secagent', 'hosts'), { recursive: true });
    const record = await scanNoAi(dir);
    const actual = EXPECTED.map(([check, host]) => {
      const r = record.results.find((x) => x.check_id === check && x.target === host);
      return `${check}@${host}=${r?.outcome ?? 'missing'}`;
    });
    expect(actual).toEqual(EXPECTED.map(([check, host, outcome]) => `${check}@${host}=${outcome}`));
    const third = record.results.find((x) => x.check_id === 'host-package-third-party' && x.target === 'bad-host');
    expect(third?.observed).toContain('nginx 1.30.6-1~trixie (installed locally, not from any configured repository)');
    const advisories = record.results.filter((x) => x.check_id === 'host-package-advisories');
    expect(advisories.map((a) => a.outcome)).not.toContain('error');
  }, 180_000);
});
