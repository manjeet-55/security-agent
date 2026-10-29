import { describe, expect, it } from 'vitest';
import { fingerprint, isPlaceholderValue, scanLine, scanText, shannonEntropy, type PatternId } from '../../src/code/patterns.js';
import { FAKE, PLANTED_LINES } from '../helpers/secrets.js';

const ids = (line: string, opts = { generic: true }): PatternId[] => scanLine(line, opts).map((h) => h.pattern);

describe('secret patterns', () => {
  it.each(Object.entries(PLANTED_LINES))('detects %s', (id, line) => {
    expect(ids(line)).toContain(id);
  });

  it('reports each hit with a fingerprint only, never the value', () => {
    const [hit] = scanLine(`const id = '${FAKE.awsKeyId}';`, { generic: false });
    expect(hit).toEqual({ pattern: 'aws-access-key-id', fingerprint: fingerprint(FAKE.awsKeyId) });
    expect(fingerprint(FAKE.awsKeyId)).toMatch(/^[0-9a-f]{8}$/);
    expect(JSON.stringify(hit)).not.toContain(FAKE.awsKeyId);
  });

  describe('near misses', () => {
    const cases: Array<[string, string]> = [
      ['aws id too short', 'AK' + 'IA' + 'Q7XJ2M5PZK3N8WD'],
      ['aws id with a lowercase tail', 'AK' + 'IA' + 'q7xj2m5pzk3n8wdv'],
      ['aws documentation example id', FAKE.awsExampleKeyId],
      ['a public key header', '-----BEGIN ' + 'PUBLIC KEY-----'],
      ['a certificate header', '-----BEGIN ' + 'CERTIFICATE-----'],
      ['github token too short', 'gh' + 'p_' + 'abc123'],
      ['slack token too short', 'xo' + 'xb-' + '12345'],
      ['stripe test key', 'sk' + '_test_' + 'Zx9Qw8Er7Ty6Ui5Op4As3Df2'],
      ['google key too short', 'AI' + 'za' + 'SyA1b2C3'],
      ['jwt with a short payload', 'ey' + 'JhbGciOiJIUzI1NiJ9.' + 'ey' + 'Jz.abc'],
    ];
    it.each(cases)('ignores %s', (_name, line) => {
      expect(ids(line)).toEqual([]);
    });
  });

  describe('url-credentials placeholders', () => {
    const placeholders = [
      'postgres://user:pass@localhost/db',
      'postgres://user:password@localhost/db',
      'https://username:password@example.com/x',
      'mysql://${DB_USER}:${DB_PASS}@db/app',
      'mysql://<user>:<password>@db/app',
      'mysql://{{user}}:{{password}}@db/app',
      'redis://default:$REDIS_PASSWORD@cache:6379',
      'postgres://app:changeme@db/app',
    ];
    it.each(placeholders)('ignores %s', (line) => {
      expect(ids(line)).not.toContain('url-credentials');
    });
    it('still flags a real-looking password', () => {
      expect(ids(`postgres://app_user:${FAKE.urlPassword}@db.internal/app`)).toContain('url-credentials');
    });
    it('ignores URLs without credentials', () => {
      expect(ids('https://example.com:8080/path?a=b@c')).not.toContain('url-credentials');
    });
  });

  describe('generic-secret-assignment', () => {
    const quiet = [
      'api_key = "your_api_key_here_please"',
      'password: "changeme-changeme"',
      'secret = "example-secret-value"',
      'token = "xxxxxxxxxxxxxxxxxxxx"',
      'const password = "dummyPasswordValue"',
      'auth_token = "test-token-for-the-suite"',
      'client_secret = "sample-client-secret"',
      'api_key = "<your-api-key-goes-here>"',
      'api_key = "${API_KEY_FROM_ENV_VAR}"',
      'password = "process.env.DB_PASSWORD_VALUE"',
      'secret = "os.environ.get_secret_value"',
      'token = "getenv_token_lookup_name"',
      'api_key = "config.services.stripe_key"',
      'password = "aaaaaaaaaaaaaaaaaaaa"',
      'password = "abababababababababab"',
      'api_key = "short"',
      'const title = "this is a long sentence value"',
    ];
    it.each(quiet)('ignores %s', (line) => {
      expect(ids(line)).not.toContain('generic-secret-assignment');
    });
    it.each(['null', 'none', 'true', 'false'])('ignores the literal %s', (v) => {
      expect(ids(`api_key = "${v}"`)).not.toContain('generic-secret-assignment');
    });
    it('is not applied when generic scanning is off (docs, lockfiles, history)', () => {
      expect(ids(PLANTED_LINES['generic-secret-assignment'] ?? '', { generic: false })).toEqual([]);
    });
    it('matches assignments with a prefix on the name, in any case, with : or =', () => {
      expect(ids(`STRIPE_API_KEY = "${FAKE.genericValue}"`)).toContain('generic-secret-assignment');
      expect(ids(`db_password: '${FAKE.genericValue}'`)).toContain('generic-secret-assignment');
      expect(ids(`"clientSecret": "${FAKE.genericValue}"`)).toContain('generic-secret-assignment');
    });
    it('does not report the generic hit twice when a high-confidence pattern already covers the value', () => {
      expect(ids(`aws_secret_key = "${FAKE.githubToken}"`)).toEqual(['github-token']);
    });
  });

  it('skips a line carrying secagent:ignore', () => {
    expect(ids(`const id = '${FAKE.awsKeyId}'; // secagent:ignore`)).toEqual([]);
  });

  it('keeps linear time on pathological lines', () => {
    const start = performance.now();
    scanLine('auth'.repeat(200_000), { generic: true });
    scanLine(`://${'a:'.repeat(200_000)}`, { generic: true });
    expect(performance.now() - start).toBeLessThan(2000);
  });
});

describe('scanText', () => {
  it('numbers lines from 1 across LF and CRLF, deterministically ordered, deduplicated', () => {
    const text = ['ok', `one ${FAKE.awsKeyId}`, '', `two ${FAKE.githubToken} and ${FAKE.githubToken}`, `three ${FAKE.awsKeyId}`].join('\r\n');
    expect(scanText(text, { generic: false })).toEqual([
      { line: 2, pattern: 'aws-access-key-id', fingerprint: fingerprint(FAKE.awsKeyId) },
      { line: 4, pattern: 'github-token', fingerprint: fingerprint(FAKE.githubToken) },
      { line: 5, pattern: 'aws-access-key-id', fingerprint: fingerprint(FAKE.awsKeyId) },
    ]);
  });
});

describe('helpers', () => {
  it('computes Shannon entropy per character', () => {
    expect(shannonEntropy('aaaa')).toBe(0);
    expect(shannonEntropy('abab')).toBeCloseTo(1, 5);
    expect(shannonEntropy('abcdefgh')).toBeCloseTo(3, 5);
    expect(shannonEntropy(FAKE.genericValue)).toBeGreaterThanOrEqual(3.5);
  });
  it('recognises placeholder values', () => {
    expect(isPlaceholderValue('changeme')).toBe(true);
    expect(isPlaceholderValue('YOUR_API_KEY')).toBe(true);
    expect(isPlaceholderValue(FAKE.genericValue)).toBe(false);
  });
});
