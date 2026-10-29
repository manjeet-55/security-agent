import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../src/checks/errors.js';
import { evaluateHostConfig, hostConfigParams } from '../../src/checks/types/host-config.js';
import { COLLECTOR_PATH, makeCollector } from '../../src/host/collector.js';
import { decodeSnapshot } from '../../src/host/snapshot.js';
import { fixtureEnvelope, withSection } from '../helpers/snapshots.js';

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

  // The collector runs under whatever awk the host has: Debian and Ubuntu default to mawk, others to gawk or busybox.
  const awks = ['mawk', 'gawk', 'busybox awk'].filter((a) => spawnSync('sh', ['-c', `command -v ${a.split(' ')[0]}`]).status === 0);
  const redactWith = (input: string, awk: string): string => {
    const run = spawnSync('sh', ['-c', `awk() { ${awk} "$@"; }\n${extractRedact()}\nredact`], { input, encoding: 'utf8' });
    expect(run.status).toBe(0);
    return run.stdout;
  };

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

  const MARKER = '# secagent: redaction lost sync';
  const sslProtocols = hostConfigParams.parse({
    rule: 'nginx_directive',
    directive: 'ssl_protocols',
    forbid_tokens: ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'],
    when_absent: 'unverifiable',
  });
  const decodeNginx = (nginx: string) => decodeSnapshot(withSection(fixtureEnvelope('ubuntu-24-04'), 'nginx', nginx));

  describe.each(awks)('quote-aware redaction that fails closed (%s)', (awk) => {
    it('an apostrophe inside a one-line map does not swallow the config after it, so ssl_protocols TLSv1 still fails', () => {
      const raw = [
        '# configuration file /etc/nginx/nginx.conf:',
        'http {',
        '\tssl_protocols TLSv1.2 TLSv1.3;',
        "\tmap $http_user_agent $is_bot { ~*o'reilly|bot LEAK_MAP_1; default 0; }",
        '\tinclude /etc/nginx/sites-enabled/*;',
        '# configuration file /etc/nginx/sites-enabled/legacy:',
        '\tserver {',
        '\t\tlisten 443 ssl;',
        '\t\tssl_protocols TLSv1 TLSv1.1 TLSv1.2;',
        '\t}',
        '}',
      ].join('\n');
      const out = redactWith(raw, awk);
      expect(out).not.toContain('LEAK_MAP_1');
      expect(out).toContain('map $http_user_agent $is_bot { <redacted> }');
      expect(out).toContain('ssl_protocols TLSv1 TLSv1.1 TLSv1.2;');
      expect(out).not.toContain(MARKER);
      expect(evaluateHostConfig(decodeNginx(out), sslProtocols)).toMatchObject({ outcome: 'fail' });
    });

    it('a map that closes mid-line keeps whatever follows its closing brace', () => {
      const out = redactWith(['map $a $b { "LEAK_MAP_2" 1; } server { ssl_protocols TLSv1; }', 'map $c $d {', '  "LEAK_MAP_3" 1;', '} ssl_protocols TLSv1.1;'].join('\n'), awk);
      expect(out).not.toMatch(/LEAK_MAP_[23]/);
      expect(out).toContain('server { ssl_protocols TLSv1; }');
      expect(out).toContain('ssl_protocols TLSv1.1;');
    });

    it('an escaped quote in a continued header value does not leave the header open', () => {
      const out = redactWith(
        ['\tproxy_set_header Authorization', '\t    "Basic LEAK_ESC_1\\"LEAK_ESC_2";', '\tssl_protocols TLSv1 TLSv1.2;', '\tserver_tokens on;'].join('\n'),
        awk,
      );
      expect(out).not.toMatch(/LEAK_ESC/);
      expect(out).toContain('proxy_set_header Authorization\n');
      expect(out).toContain('ssl_protocols TLSv1 TLSv1.2;');
      expect(out).toContain('server_tokens on;');
      expect(out).not.toContain(MARKER);
    });

    it('a quote only opens at the start of a token, and a header continuation ends after one statement', () => {
      const out = redactWith(
        [
          "\tproxy_set_header Authorization 'LEAK_Q_1'; add_header X-Note it's-fine;",
          '\tproxy_set_header Authorization',
          "\t    don't-LEAK_Q_2;",
          '\tssl_protocols TLSv1 TLSv1.2;',
        ].join('\n'),
        awk,
      );
      expect(out).not.toMatch(/LEAK_Q/);
      expect(out).toContain("add_header X-Note it's-fine;");
      expect(out).toContain('ssl_protocols TLSv1 TLSv1.2;');
    });

    it('a map body that does not parse emits the lost-sync marker instead of eating the config', () => {
      const out = redactWith(
        ['http {', '\tmap $a $b {', '\t    ~x 1;', '\tserver {', '\t\tlisten 443 ssl;', '\t\tssl_protocols TLSv1;', '\t}', '}'].join('\n'),
        awk,
      );
      expect(out.split('\n').filter((l) => l === MARKER)).toHaveLength(1);
      expect(out).toContain('ssl_protocols TLSv1;');
      expect(out).not.toContain('~x 1');
    });

    it.each([
      ['a line ending in an opening brace', ['map $a $b {', '  x 1;', '  location /x {', '}'].join('\n')],
      ['a line starting with server', ['geo $g {', '  default 0;', '  server_name_is_not_this 1;', 'server', '}'].join('\n')],
      ['a line starting with upstream', ['map $a $b {', '  upstream foo', '}'].join('\n')],
      ['a body that never closes', ['http {', 'map $a $b {', '  x 1;'].join('\n')],
    ])('lost sync is flagged for %s', (_name, raw) => {
      const out = redactWith(raw, awk);
      expect(out.split('\n')).toContain(MARKER);
    });

    it('does not flag lost sync for map entries that merely begin with server or http', () => {
      const out = redactWith(['map $host $up {', '  server1.example.com a;', '  http-only b;', '  default c;', '}'].join('\n'), awk);
      expect(out).not.toContain(MARKER);
      expect(out).not.toMatch(/server1|http-only/);
    });

    it('decodes a section carrying the marker as unreadable, so the nginx check is unverifiable and never passes', () => {
      const out = redactWith(['http {', '\tssl_protocols TLSv1.2;', '\tmap $a $b {', '\t    ~x 1;', '\tserver {', '\t\tssl_protocols TLSv1;', '\t}', '}'].join('\n'), awk);
      const snap = decodeNginx(out);
      expect(snap.nginx).toMatchObject({ state: 'error', code: 'REDACTION_LOST_SYNC' });
      expect(() => evaluateHostConfig(snap, sslProtocols)).toThrow(expect.objectContaining({ name: 'ObservationError', code: 'REDACTION_LOST_SYNC' }));
      expect(() => evaluateHostConfig(snap, sslProtocols)).toThrow(ObservationError);
    });
  });

  describe.each(awks)('quoted cookies, header values on later lines, Lua and password params (%s)', (awk) => {
    it('redacts the whole quoted value of a cookie header or parameter, even with a semicolon inside', () => {
      const out = redactWith(
        [
          '\tproxy_set_header Cookie "theme=dark; sessionid=LEAK_CK_1";',
          "\tproxy_set_header Cookie 'a=1; b=LEAK_CK_2' ;",
          '\tfastcgi_param HTTP_COOKIE "a=1; token=LEAK_CK_3";',
          '\tadd_header Set-Cookie "sid=LEAK_CK_4; Path=/; HttpOnly";',
          '\tproxy_set_header "X-Api-Key" "LEAK_CK_5;still";',
          '\tproxy_set_header Host $host;',
          '\tssl_protocols TLSv1 TLSv1.2;',
        ].join('\n'),
        awk,
      );
      expect(out).not.toMatch(/LEAK_CK|HttpOnly|sessionid|Path=/);
      expect(out).toContain('proxy_set_header Cookie <redacted>;');
      expect(out).toContain('fastcgi_param HTTP_COOKIE <redacted>;');
      expect(out).toContain('proxy_set_header Host $host;');
      expect(out).toContain('ssl_protocols TLSv1 TLSv1.2;');
    });

    it('redacts a multi-line quoted header value and keeps the statements around it', () => {
      const out = redactWith(
        ['\tproxy_set_header Authorization "Basic LEAK_ML_1', '\t    continued LEAK_ML_2; LEAK_ML_3";', '\tserver_tokens on;'].join('\n'),
        awk,
      );
      expect(out).not.toMatch(/LEAK_ML/);
      expect(out).toContain('server_tokens on;');
    });

    it('redacts more_set_headers and more_set_input_headers values that start on the next line', () => {
      const out = redactWith(
        [
          '\tmore_set_headers',
          '\t    "Authorization: Basic LEAK_MS_1";',
          '\tmore_set_input_headers -s 401',
          '\t    "X-Ok: fine"',
          '\t    "X-Api-Key: LEAK_MS_2";',
          '\tmore_set_headers "X-Foo: bar"',
          "\t    'Set-Cookie: sid=LEAK_MS_3; Path=/';",
          '\tserver_tokens on;',
        ].join('\n'),
        awk,
      );
      expect(out).not.toMatch(/LEAK_MS/);
      expect(out).toContain('server_tokens on;');
    });

    it('redacts a header value after a comment, whether the comment is on the name line or on lines of its own', () => {
      const out = redactWith(
        [
          '\tproxy_set_header Authorization # the credential',
          '\t    "Basic LEAK_CM_1";',
          '\tproxy_set_header Authorization',
          '\t    # was: proxy_set_header Authorization "Basic LEAK_CM_2";',
          '',
          '\t    "Basic LEAK_CM_3";',
          '\tproxy_set_header Cookie # c',
          '\t    # c2',
          '\t    "a=b; LEAK_CM_4";',
          '\t# proxy_set_header Authorization',
          '\tproxy_set_header Host $host;',
          '\tssl_protocols TLSv1 TLSv1.2;',
        ].join('\n'),
        awk,
      );
      expect(out).not.toMatch(/LEAK_CM/);
      expect(out).toContain('proxy_set_header Host $host;');
      expect(out).toContain('ssl_protocols TLSv1 TLSv1.2;');
      expect(out).not.toContain(MARKER);
    });

    it('redacts *_by_lua_block bodies whole, like map and geo', () => {
      const out = redactWith(
        [
          'http {',
          '\tinit_by_lua_block {',
          '\t    local key = "LEAK_LUA_1"',
          '\t    local s = "}"   -- LEAK_LUA_2 }',
          "\t    local t = '{LEAK_LUA_3'",
          '\t    ngx.shared.d:set("k", "LEAK_LUA_4")',
          '\t}',
          '\tserver_tokens on;',
          '\tset_by_lua_block $x { return "LEAK_LUA_5" }',
          '\tlocation /h { content_by_lua_block { ngx.say("LEAK_LUA_6") } }',
          '\tcontent_by_lua_block',
          '\t{',
          '\t    ngx.say("LEAK_LUA_7")',
          '\t}',
          '\tssl_protocols TLSv1 TLSv1.2;',
          '}',
        ].join('\n'),
        awk,
      );
      expect(out).not.toMatch(/LEAK_LUA/);
      expect(out).not.toContain(MARKER);
      expect(out).toContain('init_by_lua_block {');
      expect(out).toContain('server_tokens on;');
      expect(out).toContain('location /h {');
      expect(out).toContain('ssl_protocols TLSv1 TLSv1.2;');
    });

    it('flags lost sync when a Lua body contains configuration instead of code, and when it never closes', () => {
      const broken = redactWith(['access_by_lua_block {', '\tlocal x = 1', 'server {', '\tssl_protocols TLSv1;', '}'].join('\n'), awk);
      expect(broken.split('\n')).toContain(MARKER);
      expect(broken).toContain('ssl_protocols TLSv1;');
      expect(redactWith(['http {', 'log_by_lua_block {', '  local x = 1'].join('\n'), awk).split('\n')).toContain(MARKER);
      expect(redactWith(['http {', "content_by_lua '", '  local x = 1', 'server_tokens on;'].join('\n'), awk).split('\n')).toContain(MARKER);
    });

    it('redacts *_by_lua inline strings, single or double quoted and over several lines', () => {
      const out = redactWith(
        [
          "\tcontent_by_lua 'ngx.say(\"LEAK_IL_1\")';",
          '\taccess_by_lua "return ngx.var.LEAK_IL_2";',
          '\tset_by_lua $y \'return "LEAK_IL_3"\';',
          "\tcontent_by_lua '",
          '\t    local k = "LEAK_IL_4";',
          '\t    # still lua LEAK_IL_5',
          "\t';",
          '\tcontent_by_lua_file /etc/nginx/handler.lua;',
          '\tserver_tokens on;',
        ].join('\n'),
        awk,
      );
      expect(out).not.toMatch(/LEAK_IL/);
      expect(out).toContain('content_by_lua_file /etc/nginx/handler.lua;');
      expect(out).toContain('server_tokens on;');
      expect(out).not.toContain(MARKER);
    });

    it('redacts parameter and env names containing pass or pwd but leaves the *_pass directives alone', () => {
      const out = redactWith(
        [
          '\tuwsgi_param DB_PASS LEAK_PW_1;',
          '\tfastcgi_param MYSQL_PWD "LEAK_PW_2";',
          '\tscgi_param mysql_pwd LEAK_PW_3;',
          '\tfastcgi_param DB_PASSWORD LEAK_PW_4;',
          'env MYSQL_PWD=LEAK_PW_5;',
          'env DB_PASS=LEAK_PW_6;',
          'env TZ;',
          '\tproxy_pass http://backend:8080;',
          '\tproxy_pass http://upstream_pool/path;',
          '\tfastcgi_pass unix:/run/php/php8.3-fpm.sock;',
          '\tuwsgi_pass 127.0.0.1:3031;',
          '\tgrpc_pass grpc://127.0.0.1:9000;',
          '\tscgi_pass 127.0.0.1:4000;',
          '\tfastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;',
          '\tfastcgi_param REDIRECT_STATUS 200;',
        ].join('\n'),
        awk,
      );
      expect(out).not.toMatch(/LEAK_PW/);
      for (const kept of [
        'env TZ;',
        'proxy_pass http://backend:8080;',
        'proxy_pass http://upstream_pool/path;',
        'fastcgi_pass unix:/run/php/php8.3-fpm.sock;',
        'uwsgi_pass 127.0.0.1:3031;',
        'grpc_pass grpc://127.0.0.1:9000;',
        'scgi_pass 127.0.0.1:4000;',
        'fastcgi_param SCRIPT_FILENAME $document_root$fastcgi_script_name;',
        'fastcgi_param REDIRECT_STATUS 200;',
      ])
        expect(out, kept).toContain(kept);
    });

    it('redacts mail auth_http_header like the other header directives', () => {
      const out = redactWith(
        ['mail {', '\tauth_http_header X-Auth-Key "LEAK_MH_1";', '\tauth_http_header Auth-Pass LEAK_MH_2;', '\tauth_http_header X-Trace on;', '}'].join('\n'),
        awk,
      );
      expect(out).not.toMatch(/LEAK_MH/);
      expect(out).toContain('auth_http_header X-Trace on;');
    });

    it('keeps sshd -T output (no semicolons) intact', () => {
      const sshd = ['passwordauthentication yes', 'permitrootlogin without-password', 'pubkeyauthentication yes', 'kbdinteractiveauthentication no', 'server_tokens off'].join('\n');
      expect(redactWith(sshd, awk)).toBe(`${sshd}\n`);
    });
  });

  // Redaction runs over every section, and the committed fixtures are real, already redacted collector output: a second pass over
  // them must change nothing, or the new rules would be eating config the checks read.
  describe.each(awks)('redaction over the real fixtures (%s)', (awk) => {
    it.each(['ubuntu-24-04', 'ubuntu-22-04', 'debian-12'] as const)('leaves every %s section byte-identical', (name) => {
      for (const [section, { b64 }] of Object.entries(fixtureEnvelope(name).sections)) {
        const text = Buffer.from(b64, 'base64').toString('utf8').replace(/\n+$/, '');
        expect(redactWith(text, awk).replace(/\n+$/, ''), `${name} ${section}`).toBe(text);
      }
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
