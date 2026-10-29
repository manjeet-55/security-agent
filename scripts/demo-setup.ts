import { execFileSync } from 'node:child_process';
import { mkdir, readdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { pathToFileURL } from 'node:url';

/**
 * A sample project that leaks in the four ways the code checks look for, for demos. Every fake credential is built from pieces at
 * run time, so this repository itself never holds a token-shaped string that a secret scanner would flag.
 */
const FAKE_AWS_KEY_ID = 'AK' + 'IA' + 'Q7XJ2M5PZK3N8WDV';
const FAKE_STRIPE_KEY = 'sk' + '_live_' + 'Zx9Qw8Er7Ty6Ui5Op4As3Df2';
const FAKE_GITHUB_TOKEN = 'gh' + 'p_' + 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8';
const FAKE_KEY_HEADER = '-----BEGIN ' + 'RSA PRIVATE KEY-----';

function git(dir: string, ...args: string[]): void {
  const env = Object.fromEntries(Object.entries(process.env).filter(([k]) => !k.startsWith('GIT_')));
  execFileSync('git', ['-c', 'user.name=Demo', '-c', 'user.email=demo@example.com', '-c', 'commit.gpgsign=false', ...args], {
    cwd: dir,
    env: { ...env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null' },
    stdio: 'ignore',
  });
}

async function put(dir: string, rel: string, content: string): Promise<void> {
  await mkdir(path.dirname(path.join(dir, rel)), { recursive: true });
  await writeFile(path.join(dir, rel), content, 'utf8');
}

/**
 * Creates the demo project in `dir` (which must be empty or not exist yet): hard-coded cloud and payment keys, a committed .env,
 * a token that one commit adds and the next removes (so it lives on in history), and a private key that nothing ignores yet.
 */
export async function createDemoProject(dir: string): Promise<void> {
  await mkdir(dir, { recursive: true });
  if ((await readdir(dir)).length > 0) throw new Error(`${dir} is not empty; pick a new folder for the demo project`);
  git(dir, 'init', '-q', '-b', 'main');
  await put(dir, 'package.json', `${JSON.stringify({ name: 'demo-shop', version: '1.0.0', dependencies: { express: '4.17.1', lodash: '4.17.15' } }, null, 2)}\n`);
  // Old versions with published advisories, so the dependency check has something to find.
  const lock = {
    name: 'demo-shop',
    version: '1.0.0',
    lockfileVersion: 3,
    requires: true,
    packages: {
      '': { name: 'demo-shop', version: '1.0.0', dependencies: { express: '4.17.1', lodash: '4.17.15' } },
      'node_modules/express': { version: '4.17.1' },
      'node_modules/lodash': { version: '4.17.15' },
    },
  };
  await put(dir, 'package-lock.json', `${JSON.stringify(lock, null, 2)}\n`);
  await put(dir, 'src/config.js', `// Payment and cloud settings for the demo shop.\nmodule.exports = {\n  awsAccessKeyId: '${FAKE_AWS_KEY_ID}',\n  stripeSecretKey: '${FAKE_STRIPE_KEY}',\n};\n`);
  await put(dir, '.env', 'DB_PASSWORD=demo-password\nSESSION_SECRET=demo-secret\n');
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'Initial shop');
  await put(dir, 'deploy/key.txt', `GITHUB_TOKEN=${FAKE_GITHUB_TOKEN}\n`);
  git(dir, 'add', '-A');
  git(dir, 'commit', '-q', '-m', 'Add deploy token');
  git(dir, 'rm', '-q', 'deploy/key.txt');
  git(dir, 'commit', '-q', '-m', 'Remove deploy token');
  await put(dir, 'server.key', `${FAKE_KEY_HEADER}\nMIIEowIBAAKCAQEAdemo-not-a-real-key\n-----END RSA PRIVATE KEY-----\n`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const dir = process.argv[2];
  if (!dir) {
    console.error('Usage: npm run demo:setup -- <new folder>');
    process.exitCode = 1;
  } else {
    createDemoProject(path.resolve(dir)).then(
      () => console.log(`Demo project created in ${path.resolve(dir)}\nNext:  npm run demo:server   (in another terminal)\nThen:  cd ${path.resolve(dir)} && secagent`),
      (e: unknown) => {
        console.error(e instanceof Error ? e.message : e);
        process.exitCode = 1;
      },
    );
  }
}
