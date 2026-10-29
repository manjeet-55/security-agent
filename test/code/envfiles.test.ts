import { describe, expect, it } from 'vitest';
import { classifySensitiveFile, npmrcHoldsAuthToken } from '../../src/code/envfiles.js';

describe('classifySensitiveFile', () => {
  it.each([
    ['.env', 'env-file'],
    ['.env.local', 'env-file'],
    ['.env.production', 'env-file'],
    ['config/.env', 'env-file'],
    ['apps/web/.env.development.local', 'env-file'],
    ['.ENV', 'env-file'],
    ['certs/server.pem', 'private-key-file'],
    ['tls/site.key', 'private-key-file'],
    ['store.p12', 'private-key-file'],
    ['store.pfx', 'private-key-file'],
    ['deploy/id_rsa', 'private-key-file'],
    ['id_ed25519', 'private-key-file'],
    ['id_ecdsa', 'private-key-file'],
    ['id_rsa.backup', 'private-key-file'],
    ['credentials.json', 'credentials-file'],
    ['gcp/credentials-prod.json', 'credentials-file'],
    ['infra/terraform.tfstate', 'terraform-state'],
    ['infra/terraform.tfstate.backup', 'terraform-state'],
    ['home/.aws/credentials', 'aws-credentials'],
    ['.aws/credentials', 'aws-credentials'],
    ['.npmrc', 'npmrc'],
    ['packages/app/.npmrc', 'npmrc'],
  ])('%s is a %s', (name, kind) => {
    expect(classifySensitiveFile(name)).toBe(kind);
  });

  it.each([
    '.env.example',
    '.env.sample',
    '.env.template',
    '.env.dist',
    '.env.defaults',
    '.env.local.example',
    '.ENV.EXAMPLE',
    'id_rsa.pub',
    'id_ed25519.pub',
    'environment.ts',
    'env.js',
    'myenv',
    'src/.envrc',
    'credentials.ts',
    'credentials.json.md',
    'docs/aws/credentials.md',
    'keyboard.ts',
    'monkey.keys',
    'terraform.tf',
    'README.md',
    '.gitignore',
  ])('%s is not sensitive by name', (name) => {
    expect(classifySensitiveFile(name)).toBeUndefined();
  });
});

describe('npmrcHoldsAuthToken', () => {
  it.each([
    '//registry.npmjs.org/:_authToken=abcdef0123456789abcdef',
    '//registry.example.org/:_authToken = abcdef0123456789\n',
    'registry=https://registry.example.org/\n//registry.example.org/:_authToken="abcdef0123456789"\n',
    '_authToken=abcdef0123456789',
  ])('detects a literal token in %j', (text) => {
    expect(npmrcHoldsAuthToken(text)).toBe(true);
  });

  it.each([
    '//registry.npmjs.org/:_authToken=${NPM_TOKEN}',
    '//registry.npmjs.org/:_authToken=$NPM_TOKEN',
    '//registry.npmjs.org/:_authToken=',
    '# _authToken=abcdef0123456789',
    '; _authToken=abcdef0123456789',
    'registry=https://registry.npmjs.org/\nsave-exact=true\n',
    '',
  ])('does not flag %j', (text) => {
    expect(npmrcHoldsAuthToken(text)).toBe(false);
  });
});
