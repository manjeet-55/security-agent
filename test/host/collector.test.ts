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

  const extractRedact = () => /redact\(\) \{[\s\S]*?\n\}/.exec(SCRIPT)?.[0] ?? '';

  it('redacts env values, secret-named directives, URL query credentials, continued headers and brace-on-next-line maps', () => {
    const input = [
      'env SECRET_ENVVAL=envsecret77;',
      'env TZ;',
      'http {',
      '\tserver_tokens off;',
      '\tsecure_link_secret linksecret55;',
      '\tauth_jwt_key "jwtkeyval99";',
      '\tauth_jwt_key_file /etc/nginx/jwt.key;',
      '\tssl_password_file /etc/nginx/pass.txt;',
      '\tproxy_pass http://up.example.invalid/x?api_key=querysecret1&mode=fast&sig=sigval22;',
      '\tproxy_set_header Authorization',
      '\t    "Bearer-less-continued-secret";',
      '\tproxy_set_header Host $host;',
      '\tmap $a $b',
      '\t{',
      '\t    "nextlinemapsecret" 1;',
      '\t    default 0;',
      '\t}',
      '\tgeo $g',
      '{',
      '    10.1.0.0/16 geonextsecret;',
      '}',
      '\tlisten 443 ssl;',
      '}',
    ].join('\n');
    const run = spawnSync('sh', ['-c', `${extractRedact()}\nredact`], { input, encoding: 'utf8' });
    expect(run.status).toBe(0);
    const out = run.stdout;
    for (const secret of ['envsecret77', 'linksecret55', 'jwtkeyval99', 'querysecret1', 'sigval22', 'continued-secret', 'nextlinemapsecret', 'geonextsecret'])
      expect(out).not.toContain(secret);
    for (const kept of [
      'env TZ;',
      'server_tokens off;',
      'auth_jwt_key_file /etc/nginx/jwt.key;',
      'ssl_password_file /etc/nginx/pass.txt;',
      'mode=fast',
      'proxy_set_header Host $host;',
      'listen 443 ssl;',
      'proxy_set_header Authorization',
    ])
      expect(out).toContain(kept);
    expect(out).toContain('env SECRET_ENVVAL=<redacted>;');
  });

  describe('redaction hardening (secure_link, headers-more, comments, one-line blocks, blank lines, brace counting)', () => {
    const input = [
      '\tsecure_link_md5 "$secure_link_expires$uri$remote_addr LEAK_MD5_SECRET";',
      '\tsecure_link_secret LEAK_TRAILCOMMENT; # used by /dl',
      '\tlocation /p { secure_link_secret LEAK_INLINE_BLOCK; }',
      '\tsecure_link_secret "LEAK_QUOTED;SEMICOLON"; # c',
      '\t# secure_link_secret LEAK_COMMENTED_OUT;',
      '\tmore_set_headers "Authorization: Basic LEAK_MORESET_BASIC";',
      '\tmore_set_input_headers "Authorization: Basic LEAK_MORESETINPUT";',
      "\tmore_set_headers 'X-Api-Key: LEAK_MORESET_APIKEY';",
      "\tmore_set_headers -s 200 'Set-Cookie: sid=LEAK_MORESET_COOKIE' 'X-Frame-Options: DENY';",
      '\tmore_set_headers X-Session-Token:LEAK_MORESET_BARE;',
      "\tmore_set_headers 'Server: nginx';",
      '\tset $jwt "LEAK_SETJWT";',
      '\tset $my_jwt_value LEAK_SETJWT2;',
      '\tproxy_set_header Authorization',
      '',
      '\t# the value follows',
      '\t    "Basic LEAK_AFTER_BLANK";',
      '\tapi_key LEAK_APIKEY_DIRECTIVE;',
      '\tsecure_link_secret',
      '\t    LEAK_NEXTLINE_DIRECTIVE;',
      '\tmap $uri $x {',
      '\t    ~^/a{2}$ LEAK_BEFORE_REGEX_BRACE;',
      '\t    "LEAK_AFTER_REGEX_BRACE" 2;',
      '\t    "~^(a|b){1,3}$" LEAK_AFTER_QUOTED_BRACES;',
      '\t    default 0;',
      '\t}',
      '\tgeo $g {',
      '\t    default 0;',
      '\t    10.0.0.0/8 LEAK_GEO_NESTED; # { not a block',
      '\t}',
      '\tserver_tokens off;',
      '\tssl_protocols TLSv1.2 TLSv1.3;',
      '\tssl_password_file /etc/nginx/pw.txt;',
      '\tproxy_set_header Host $host;',
      '\tlisten 443 ssl; # token rotation: monthly',
    ].join('\n');
    const secrets = [
      'LEAK_MD5_SECRET', 'LEAK_TRAILCOMMENT', 'LEAK_INLINE_BLOCK', 'SEMICOLON', 'LEAK_COMMENTED_OUT', 'LEAK_MORESET_BASIC', 'LEAK_MORESETINPUT',
      'LEAK_MORESET_APIKEY', 'LEAK_MORESET_COOKIE', 'LEAK_MORESET_BARE', 'LEAK_SETJWT', 'LEAK_SETJWT2', 'LEAK_AFTER_BLANK', 'LEAK_APIKEY_DIRECTIVE',
      'LEAK_NEXTLINE_DIRECTIVE', 'LEAK_BEFORE_REGEX_BRACE', 'LEAK_AFTER_REGEX_BRACE', 'LEAK_AFTER_QUOTED_BRACES', 'LEAK_GEO_NESTED',
    ];
    const kept = [
      'location /p {',
      '# used by /dl',
      "more_set_headers 'Server: nginx';",
      "'X-Frame-Options: DENY'",
      'proxy_set_header Authorization',
      'server_tokens off;',
      'ssl_protocols TLSv1.2 TLSv1.3;',
      'ssl_password_file /etc/nginx/pw.txt;',
      'proxy_set_header Host $host;',
      'listen 443 ssl;',
      'map $uri $x {',
    ];

    // The collector runs under whatever awk the host has: Debian and Ubuntu default to mawk, others to gawk or busybox.
    const awks = ['mawk', 'gawk', 'busybox awk'].filter((a) => spawnSync('sh', ['-c', `command -v ${a.split(' ')[0]}`]).status === 0);

    it.each(awks)('redacts every planted secret and keeps what the checks need (%s)', (awk) => {
      const run = spawnSync('sh', ['-c', `awk() { ${awk} "$@"; }\n${extractRedact()}\nredact`], { input, encoding: 'utf8' });
      expect(run.status).toBe(0);
      for (const secret of secrets) expect(run.stdout, secret).not.toContain(secret);
      for (const keep of kept) expect(run.stdout, keep).toContain(keep);
    });

    it('redacts the whole value of secure_link_md5 and secure_link_secret', () => {
      const run = spawnSync('sh', ['-c', `${extractRedact()}\nredact`], { input, encoding: 'utf8' });
      expect(run.stdout).toContain('secure_link_md5 <redacted>;');
      expect(run.stdout).toContain('secure_link_secret <redacted>; # used by /dl');
      expect(run.stdout).toContain('location /p { secure_link_secret <redacted>; }');
    });
  });

  it('emit yields JSON with rc and b64 per section', () => {
    const head = SCRIPT.slice(0, SCRIPT.indexOf('emit uid'));
    const script = `${head}emit ok 'echo hello'\nemit bad 'echo oops; exit 3'\nprintf '}}\\n'\n`;
    const run = spawnSync('sh', ['-c', script], { encoding: 'utf8' });
    expect(run.status).toBe(0);
    const doc = JSON.parse(run.stdout) as { schema: number; collected_at: string; sections: Record<string, { rc: number; b64: string }> };
    expect(doc.schema).toBe(1);
    expect(Object.keys(doc.sections)).toEqual(['ok', 'bad']);
    expect(doc.sections.bad?.rc).toBe(3);
    expect(Buffer.from(doc.sections.bad?.b64 ?? '', 'base64').toString()).toBe('oops\n');
    expect(doc.sections.ok?.rc).toBe(0);
    expect(Buffer.from(doc.sections.ok?.b64 ?? '', 'base64').toString()).toContain('hello');
  });
});
