import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { COLLECTOR_PATH, makeCollector } from '../../src/host/collector.js';

const SCRIPT = readFileSync(COLLECTOR_PATH, 'utf8');
const linuxWithSh = process.platform === 'linux' && existsSync('/bin/sh');

describe('makeCollector', () => {
  it('bundles the script with its sha256, drop dir and instructions', async () => {
    const b = await makeCollector('/work/app', 'web-1');
    expect(b.script).toBe(SCRIPT);
    expect(b.sha256).toBe(createHash('sha256').update(SCRIPT).digest('hex'));
    expect(b.dropDir).toBe(path.join('/work/app', '.secagent', 'hosts', 'web-1'));
    expect(b.instructions).toContain('sudo sh collect.sh > web-1.json');
    expect(b.instructions).toContain('secagent snapshot add --host web-1 web-1.json');
    expect(b.instructions).toContain(b.sha256);
  });
});

describe.runIf(linuxWithSh)('collector.sh', () => {
  it('is valid POSIX sh', () => {
    expect(spawnSync('sh', ['-n', COLLECTOR_PATH]).status).toBe(0);
  });

  it('redacts secrets but keeps config keys the checks need', () => {
    const fn = /redact\(\) \{[\s\S]*?\n\}/.exec(SCRIPT)?.[0];
    expect(fn).toBeDefined();
    const input = [
      'passwordauthentication yes',
      '\tserver_tokens off;',
      '\tset $api_token "s3cretA1";',
      '\tproxy_set_header X-Api-Key "s3cretB2";',
      '\tproxy_set_header Authorization "Bearer abcdefghijkl12345";',
      '\tproxy_set_header Host $host;',
      'deb https://user:tok3nvalue@repo.example.invalid/x stable main',
      'map $http_x_key $allowed {',
      '    "hunter2mapvalue" 1;',
      '    default 0;',
      '}',
      'map $a $b { "onelinesecret9" 1; }',
      'geo $trusted {',
      '    10.0.0.0/8 geosecretval;',
      '}',
      'deb https://ghp_TOKENONLY123@github.com/x stable main',
      'deb https://user:p@ssw0rdtail@repo.example.invalid/x stable main',
      '\tproxy_set_header X-Internal-Key "internalkeyval1";',
      '\tproxy_set_header X-Auth "authval123";',
    ].join('\n');
    const run = spawnSync('sh', ['-c', `${fn}\nredact`], { input, encoding: 'utf8' });
    expect(run.status).toBe(0);
    const out = run.stdout;
    const secrets = ['s3cretA1', 's3cretB2', 'abcdefghijkl12345', 'tok3nvalue'];
    secrets.push('hunter2mapvalue', 'onelinesecret9', 'geosecretval', 'ghp_TOKENONLY123', 'ssw0rdtail', 'internalkeyval1', 'authval123');
    for (const secret of secrets) expect(out).not.toContain(secret);
    expect(out).toContain('passwordauthentication yes');
    expect(out).toContain('server_tokens off;');
    expect(out).toContain('proxy_set_header Host $host;');
  });
});
