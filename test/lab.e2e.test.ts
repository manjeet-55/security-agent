import { cp, mkdir } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { scanNoAi } from '../src/scan/no-ai.js';
import { tempDir } from './helpers/tmp.js';

const LAB_PROJECT = path.join(import.meta.dirname, '..', 'lab', 'project', '.secagent', 'project.yaml');

const EXPECTED: Array<[check: string, target: string, outcome: string]> = [
  ['http-redirect-https', 'bad-site', 'fail'],
  ['http-redirect-https', 'good-site', 'pass'],
  ...['hdr-hsts', 'hdr-csp', 'hdr-frame-options', 'hdr-content-type-options', 'hdr-referrer-policy', 'hdr-permissions-policy', 'hdr-x-powered-by', 'hdr-server-version', 'cookie-flags'].flatMap(
    (check): Array<[string, string, string]> => [
      [check, 'bad-site', 'fail'],
      [check, 'good-site', 'pass'],
    ],
  ),
  ['header-budget', 'bad-site', 'pass'],
  ['header-budget', 'good-site', 'pass'],
  ['exposed-paths', 'bad-site', 'fail'],
  ['exposed-paths', 'good-site', 'pass'],
  ['tls-no-legacy', 'bad-site', 'fail'],
  ['tls-no-legacy', 'good-site', 'pass'],
  ['tls-modern', 'bad-site', 'fail'],
  ['tls-modern', 'good-site', 'pass'],
  ['tls-cert-valid', 'bad-site', 'fail'],
  ['tls-cert-valid', 'good-site', 'fail'],
  ['ports-exposed', 'bad-host', 'fail'],
  ['ports-exposed', 'good-host', 'pass'],
];

describe.runIf(process.env.SECAGENT_LAB === '1')('lab end-to-end (start lab/docker-compose.yml first)', () => {
  it('produces the expected outcome for every seed check', async () => {
    const dir = await tempDir();
    await mkdir(path.join(dir, '.secagent'), { recursive: true });
    await cp(LAB_PROJECT, path.join(dir, '.secagent', 'project.yaml'));
    const record = await scanNoAi(dir);
    const actual = EXPECTED.map(([check, target]) => {
      const r = record.results.find((x) => x.check_id === check && x.target === target);
      return `${check}@${target}=${r?.outcome ?? 'missing'}`;
    });
    expect(actual).toEqual(EXPECTED.map(([check, target, outcome]) => `${check}@${target}=${outcome}`));

    const exposed = record.results.find((r) => r.check_id === 'exposed-paths' && r.target === 'bad-site');
    expect(exposed?.severity).toBe('critical');
    expect(exposed?.observed).toContain('/.env');
    expect(exposed?.observed).toContain('/.git/config');
    expect(exposed?.observed).toContain('/app.js.map');
  }, 120_000);
});
