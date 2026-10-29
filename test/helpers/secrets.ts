/**
 * Fake credentials in the exact shapes the scanner looks for. Each one is joined from pieces at runtime so that this repository
 * never contains a literal that a secret scanner (ours, or a hosting provider's push protection) would flag.
 */
export const FAKE = {
  awsKeyId: 'AK' + 'IA' + 'Q7XJ2M5PZK3N8WDV',
  awsExampleKeyId: 'AK' + 'IA' + 'IOSFODNN7EXAMPLE',
  privateKeyHeader: '-----BEGIN ' + 'RSA PRIVATE KEY-----',
  privateKeyBody: 'MIIEowIBAAKCAQEA' + 'q9Zx7Wv3Lm0Pn5Rt2YbQ8dKfJh4Gs1Vc6',
  githubToken: 'gh' + 'p_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8',
  slackToken: 'xo' + 'xb-' + '123456789012-aBcDeFgHiJkL',
  stripeLiveKey: 'sk' + '_live_' + 'Zx9Qw8Er7Ty6Ui5Op4As3Df2',
  googleApiKey: 'AI' + 'za' + 'SyA1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q',
  jwt: ['ey' + 'JhbGciOiJIUzI1NiJ9', 'ey' + 'JzdWIiOiIxMjM0NTY3ODkwIn0', 'dBjftJeZ4CVPmB92K27uhbUJU1p1r'].join('.'),
  urlPassword: 'Sup3rS3cr3t' + 'Pw9xQ',
  genericValue: 'Zk3pQ9vXw2LmN8rT' + '5yB1cHd7',
} as const;

/** One planted secret per pattern id, as a line of source code. */
export const PLANTED_LINES: Record<string, string> = {
  'aws-access-key-id': `const id = '${FAKE.awsKeyId}';`,
  'private-key-block': FAKE.privateKeyHeader,
  'github-token': `GH=${FAKE.githubToken}`,
  'slack-token': `SLACK=${FAKE.slackToken}`,
  'stripe-live-key': `STRIPE=${FAKE.stripeLiveKey}`,
  'google-api-key': `key: "${FAKE.googleApiKey}"`,
  jwt: `Authorization: Bearer ${FAKE.jwt}`,
  'url-credentials': `DATABASE_URL=postgres://app_user:${FAKE.urlPassword}@db.internal:5432/app`,
  'generic-secret-assignment': `const config = { api_key: "${FAKE.genericValue}" };`,
};
