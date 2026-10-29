import { mkdir, symlink, writeFile } from 'node:fs/promises';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { describe, expect, it, vi } from 'vitest';
import { fingerprint } from '../../../src/code/patterns.js';
import { codeSecretsCheck, codeSecretsParams } from '../../../src/checks/types/code-secrets.js';
import type { CheckOutput } from '../../../src/checks/check-type.js';
import { ObservationError } from '../../../src/checks/errors.js';
import { codeSubject, makeCtx } from '../../helpers/ctx.js';
import { commitAll, git, gitInit, repoWith } from '../../helpers/git.js';
import { FAKE, PLANTED_LINES } from '../../helpers/secrets.js';
import { slowGitLog } from '../../helpers/slow-git.js';
import { tempDir, writeFiles } from '../../helpers/tmp.js';

type Ctx = Awaited<ReturnType<typeof makeCtx>>['ctx'];

async function run(dir: string, ctx: Ctx, params: Record<string, unknown> = { rule: 'working_tree' }): Promise<CheckOutput> {
  return codeSecretsCheck.run(ctx, codeSubject(dir), codeSecretsParams.parse(params), {} as never);
}

/** Runs the check the way the runner does, so an ObservationError becomes an unverifiable result. */
async function runLikeRunner(dir: string, ctx: Ctx, params: Record<string, unknown>): Promise<CheckOutput> {
  try {
    return await run(dir, ctx, params);
  } catch (e) {
    if (e instanceof ObservationError) return { outcome: 'unverifiable', observed: e.message, evidence_id: 'none' };
    throw e;
  }
}

async function evidenceOf(dir: string, out: CheckOutput): Promise<{ data: Record<string, any> }> {
  return JSON.parse(readFileSync(path.join(dir, '.secagent', 'evidence', `${out.evidence_id}.json`), 'utf8'));
}

describe('code_secrets params', () => {
  it('needs a known rule', () => {
    expect(codeSecretsParams.safeParse({ rule: 'nope' }).success).toBe(false);
    expect(codeSecretsParams.parse({ rule: 'working_tree' })).toEqual({ rule: 'working_tree' });
  });
});

describe('code_secrets working_tree', () => {
  describe.each([
    ['a git repository', true],
    ['a plain directory', false],
  ])('in %s', (_name, isRepo) => {
    async function project(files: Record<string, string>, overrides: Record<string, unknown> = {}) {
      const made = await makeCtx({}, overrides);
      if (isRepo) gitInit(made.dir);
      await writeFiles(made.dir, files);
      if (isRepo) commitAll(made.dir);
      return made;
    }

    it.each(Object.entries(PLANTED_LINES))('fails on a planted %s, reporting file, line and fingerprint but not the value', async (id, line) => {
      const { ctx, dir } = await project({ 'src/app.ts': `// header\n${line}\n` });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('fail');
      expect(out.observed).toContain(`src/app.ts:2 ${id}`);
      expect(out.observed).toMatch(/\[[0-9a-f]{8}\]/);
      const ev = await evidenceOf(dir, out);
      expect(ev.data.hits).toContainEqual({ path: 'src/app.ts', line: 2, pattern: id, fingerprint: expect.stringMatching(/^[0-9a-f]{8}$/) });
    });

    it('passes on clean code and says what it scanned', async () => {
      const { ctx, dir } = await project({ 'src/app.ts': 'export const x = 1;\n', 'README.md': '# hi\n' });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('pass');
      expect(out.observed).toContain('2 file');
    });

    it('skips placeholders and lines marked secagent:ignore', async () => {
      const { ctx, dir } = await project({
        '.env.example': 'API_KEY="your_api_key_here_please"\nDB=postgres://user:password@db/app\n',
        'src/a.ts': `const id = '${FAKE.awsKeyId}'; // secagent:ignore\n`,
      });
      expect((await run(dir, ctx)).outcome).toBe('pass');
    });

    it('applies the generic pattern to code but not to docs and lockfiles; high-confidence patterns still apply everywhere', async () => {
      const generic = PLANTED_LINES['generic-secret-assignment'] ?? '';
      const { ctx, dir } = await project({
        'docs/guide.md': `${generic}\n`,
        'notes.txt': `${generic}\n`,
        'package-lock.json': `${generic}\n`,
        'src/real.ts': `${generic}\n`,
        'docs/leak.md': `token ${FAKE.githubToken}\n`,
      });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('fail');
      const hits = (await evidenceOf(dir, out)).data.hits as Array<{ path: string; pattern: string }>;
      expect(hits.map((h) => `${h.path} ${h.pattern}`)).toEqual(['docs/leak.md github-token', 'src/real.ts generic-secret-assignment']);
    });

    it('orders hits by path then line and deduplicates identical ones', async () => {
      const { ctx, dir } = await project({
        'b.ts': `x\n${FAKE.awsKeyId} ${FAKE.awsKeyId}\n`,
        'a.ts': `${FAKE.githubToken}\n\n${FAKE.awsKeyId}\n`,
      });
      const out = await run(dir, ctx);
      const hits = (await evidenceOf(dir, out)).data.hits as Array<{ path: string; line: number }>;
      expect(hits.map((h) => `${h.path}:${h.line}`)).toEqual(['a.ts:1', 'a.ts:3', 'b.ts:2']);
    });

    it('honours code.exclude', async () => {
      const { ctx, dir } = await project(
        { 'fixtures/leak.txt': `${FAKE.awsKeyId}\n`, 'src/ok.ts': 'x\n' },
        { code: { exclude: ['fixtures/'] } },
      );
      expect((await run(dir, ctx)).outcome).toBe('pass');
    });

    it('never reads or reports the .secagent directory', async () => {
      const { ctx, dir } = await project({ 'src/ok.ts': 'x\n' });
      await writeFiles(dir, { '.secagent/knowledge/notes.md': `${FAKE.awsKeyId}\n`, '.secagent/project-copy.txt': `${FAKE.githubToken}\n` });
      expect((await run(dir, ctx)).outcome).toBe('pass');
    });

    it('is unverifiable, not a pass, when a file is larger than max_file_bytes', async () => {
      const { ctx, dir } = await project({ 'small.ts': 'x\n', 'big.sql': `${'-- filler\n'.repeat(50)}` }, { code: { max_file_bytes: 100 } });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('1 file(s) larger than 100 bytes');
      expect(out.observed).toContain('big.sql');
      expect(out.observed).toContain('does not mean');
      const ev = await evidenceOf(dir, out);
      expect(ev.data.skipped.too_large).toEqual(['big.sql']);
    });

    it('is unverifiable when there are more files than max_files', async () => {
      const files = Object.fromEntries(Array.from({ length: 5 }, (_v, i) => [`f${i}.ts`, 'x\n']));
      const { ctx, dir } = await project(files, { code: { max_files: 3 } });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('max_files');
    });

    it('still fails when it found a secret but could not scan everything, and says so', async () => {
      const { ctx, dir } = await project({ 'a.ts': `${FAKE.awsKeyId}\n`, 'big.sql': 'x'.repeat(500) }, { code: { max_file_bytes: 100 } });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('fail');
      expect(out.observed).toContain('a.ts:1');
      expect(out.observed).toContain('Not everything was scanned');
    });

    it('is unverifiable when a file cannot be read', async () => {
      if (process.getuid?.() === 0) return; // root reads everything
      const { ctx, dir } = await project({ 'ok.ts': 'x\n', 'locked.ts': 'y\n' });
      const { chmodSync } = await import('node:fs');
      chmodSync(path.join(dir, 'locked.ts'), 0o000);
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('locked.ts');
    });

    it('skips binary files without calling them unverifiable', async () => {
      const { ctx, dir } = await project({ 'src/ok.ts': 'x\n' });
      await writeFile(path.join(dir, 'blob.dat'), Buffer.concat([Buffer.from([0, 1, 2, 3]), Buffer.from(FAKE.awsKeyId)]));
      await writeFile(path.join(dir, 'logo.png'), Buffer.from(FAKE.awsKeyId));
      if (isRepo) commitAll(dir);
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('pass');
    });

    it('does not follow symlinks, so nothing outside the project is read', async () => {
      const outside = await tempDir('secagent-outside-');
      await writeFiles(outside, { 'secret.txt': `${FAKE.awsKeyId}\n`, 'dir/deep.txt': `${FAKE.githubToken}\n` });
      const { ctx, dir } = await project({ 'src/ok.ts': 'x\n' });
      await symlink(path.join(outside, 'secret.txt'), path.join(dir, 'link.txt'));
      await symlink(path.join(outside, 'dir'), path.join(dir, 'linkdir'));
      if (isRepo) commitAll(dir);
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('pass');
    });
  });

  describe('file selection', () => {
    it('in a git repository scans tracked and untracked-not-ignored files, not ignored ones', async () => {
      const { ctx, dir } = await makeCtx();
      await repoWith(dir, { '.gitignore': 'ignored.ts\n', 'tracked.ts': 'x\n' });
      await writeFiles(dir, { 'untracked.ts': `${FAKE.awsKeyId}\n`, 'ignored.ts': `${FAKE.githubToken}\n` });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('fail');
      const ev = await evidenceOf(dir, out);
      expect(ev.data.mode).toBe('git');
      expect((ev.data.hits as Array<{ path: string }>).map((h) => h.path)).toEqual(['untracked.ts']);
    });

    it('in git mode does not skip tracked files under directories the walk would exclude', async () => {
      const { ctx, dir } = await makeCtx();
      await repoWith(dir, { 'dist/bundle.js': `${FAKE.awsKeyId}\n` });
      expect((await run(dir, ctx)).outcome).toBe('fail');
    });

    it('in a plain directory walks it with default excludes', async () => {
      const { ctx, dir } = await makeCtx();
      await writeFiles(dir, {
        'src/ok.ts': 'x\n',
        'node_modules/pkg/index.js': `${FAKE.awsKeyId}\n`,
        'dist/out.js': `${FAKE.awsKeyId}\n`,
        'build/out.js': `${FAKE.awsKeyId}\n`,
        'vendor/v.php': `${FAKE.awsKeyId}\n`,
        'coverage/c.json': `${FAKE.awsKeyId}\n`,
        '.next/cache.js': `${FAKE.awsKeyId}\n`,
        '.git/config': `${FAKE.awsKeyId}\n`,
        'app.min.js': `${FAKE.awsKeyId}\n`,
        'app.js.map': `${FAKE.awsKeyId}\n`,
        'yarn.lock': `${FAKE.awsKeyId}\n`,
      });
      const out = await run(dir, ctx);
      expect(out.outcome).toBe('pass');
      const ev = await evidenceOf(dir, out);
      expect(ev.data.mode).toBe('walk');
      expect(ev.data.files_scanned).toBe(1);
    });

    it('walk mode reports an unreadable directory as unverifiable', async () => {
      if (process.getuid?.() === 0) return;
      const { ctx, dir } = await makeCtx();
      await writeFiles(dir, { 'ok.ts': 'x\n', 'locked/a.ts': 'y\n' });
      const { chmodSync } = await import('node:fs');
      chmodSync(path.join(dir, 'locked'), 0o000);
      try {
        const out = await run(dir, ctx);
        expect(out.outcome).toBe('unverifiable');
        expect(out.observed).toContain('locked');
      } finally {
        chmodSync(path.join(dir, 'locked'), 0o755);
      }
    });

    it('a project directory below the repository root only scans its own files', async () => {
      const { ctx, dir } = await makeCtx();
      await repoWith(dir, { 'other/leak.ts': `${FAKE.awsKeyId}\n`, 'app/ok.ts': 'x\n' });
      const sub = path.join(dir, 'app');
      await mkdir(path.join(sub, '.secagent'), { recursive: true });
      const out = await run(sub, ctx);
      expect(out.outcome).toBe('pass');
    });
  });

  it('writes nothing but evidence and never the secret values', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, Object.fromEntries(Object.entries(PLANTED_LINES).map(([id, line]) => [`src/${id}.txt`, `${line}\n`])));
    const out = await run(dir, ctx);
    const blob = JSON.stringify(out) + JSON.stringify(await evidenceOf(dir, out));
    for (const v of [FAKE.awsKeyId, FAKE.githubToken, FAKE.slackToken, FAKE.stripeLiveKey, FAKE.googleApiKey, FAKE.jwt, FAKE.urlPassword, FAKE.genericValue, FAKE.privateKeyBody]) {
      expect(blob).not.toContain(v);
    }
    expect(blob).toContain(fingerprint(FAKE.awsKeyId));
    expect(git(dir, 'status', '--porcelain')).toBe('?? .secagent/\n');
  });
});

const ENV_TRACKED = { rule: 'env_tracked' };
const ENV_NOT_IGNORED = { rule: 'env_not_ignored' };
const HISTORY = { rule: 'history' };

describe('code_secrets params for the git rules', () => {
  it('accepts the three git rules and the history limits, and rejects nonsense limits', () => {
    expect(codeSecretsParams.parse(ENV_TRACKED)).toEqual(ENV_TRACKED);
    expect(codeSecretsParams.parse(ENV_NOT_IGNORED)).toEqual(ENV_NOT_IGNORED);
    expect(codeSecretsParams.parse({ rule: 'history', max_commits: 5, max_diff_bytes: 1000, timeout_ms: 500 })).toMatchObject({ max_commits: 5 });
    expect(codeSecretsParams.safeParse({ rule: 'history', max_commits: 0 }).success).toBe(false);
    expect(codeSecretsParams.safeParse({ rule: 'history', timeout_ms: -1 }).success).toBe(false);
    expect(codeSecretsParams.safeParse({ rule: 'env_tracked', max_commits: 5 }).success).toBe(false);
  });
});

describe.each([
  ['env_tracked', ENV_TRACKED],
  ['env_not_ignored', ENV_NOT_IGNORED],
  ['history', HISTORY],
])('code_secrets %s outside a usable git repository', (_rule, params) => {
  it('is unverifiable in a plain directory, because there is no git to ask', async () => {
    const { ctx, dir } = await makeCtx();
    await writeFiles(dir, { '.env': 'A=1\n', 'src/a.ts': 'x\n' });
    const out = await runLikeRunner(dir, ctx, params);
    expect(out.outcome).toBe('unverifiable');
    expect(out.observed).toContain('not a git repository');
  });

  it('is unverifiable when git is not installed', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { 'a.ts': 'x\n' });
    vi.stubEnv('PATH', '');
    try {
      const out = await runLikeRunner(dir, ctx, params);
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('git was not found');
    } finally {
      vi.unstubAllEnvs();
    }
  });
});

describe('code_secrets env_tracked', () => {
  const SECRET_ENV = `DB_PASSWORD=${FAKE.urlPassword}\nTOKEN=${FAKE.githubToken}\n`;

  it.each([
    ['.env', 'environment file'],
    ['.env.production', 'environment file'],
    ['config/.env.local', 'environment file'],
    ['certs/server.pem', 'key or certificate file'],
    ['tls/site.key', 'key or certificate file'],
    ['store.p12', 'key or certificate file'],
    ['store.pfx', 'key or certificate file'],
    ['deploy/id_rsa', 'key or certificate file'],
    ['id_ed25519', 'key or certificate file'],
    ['gcp/credentials-prod.json', 'credentials file'],
    ['infra/terraform.tfstate', 'Terraform state'],
    ['infra/terraform.tfstate.backup', 'Terraform state'],
    ['home/.aws/credentials', 'AWS credentials file'],
  ])('fails when %s is tracked, naming the file and its kind', async (name, label) => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { [name]: SECRET_ENV, 'src/ok.ts': 'x\n' });
    const out = await run(dir, ctx, ENV_TRACKED);
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain(`${name} (${label})`);
    expect(out.observed).toContain('rotate');
    expect(out.observed).toContain('history');
    const ev = await evidenceOf(dir, out);
    expect(ev.data.files).toEqual([{ path: name, kind: expect.any(String) }]);
  });

  it('never prints what the file holds', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { '.env': SECRET_ENV });
    const out = await run(dir, ctx, ENV_TRACKED);
    const blob = JSON.stringify(out) + JSON.stringify(await evidenceOf(dir, out));
    expect(blob).not.toContain(FAKE.urlPassword);
    expect(blob).not.toContain(FAKE.githubToken);
  });

  it('passes on templates, public keys and look-alike names', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, {
      '.env.example': 'A=\n',
      '.env.sample': 'A=\n',
      '.env.template': 'A=\n',
      '.env.dist': 'A=\n',
      '.env.defaults': 'A=\n',
      'keys/id_rsa.pub': 'ssh-rsa AAAA\n',
      'src/environment.ts': 'x\n',
      'docs/credentials.md': 'x\n',
    });
    const out = await run(dir, ctx, ENV_TRACKED);
    expect(out.outcome).toBe('pass');
    expect(out.observed).toContain('8 tracked file(s)');
  });

  it('does not flag an untracked .env: that is the other check', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { 'a.ts': 'x\n' });
    await writeFiles(dir, { '.env': 'A=1\n' });
    expect((await run(dir, ctx, ENV_TRACKED)).outcome).toBe('pass');
  });

  it('flags a file that is tracked even though .gitignore now lists it', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { '.env': 'A=1\n' });
    await writeFiles(dir, { '.gitignore': '.env\n' });
    commitAll(dir, 'ignore it too late');
    expect((await run(dir, ctx, ENV_TRACKED)).outcome).toBe('fail');
  });

  it('flags an .npmrc only when it holds a literal auth token', async () => {
    const a = await makeCtx();
    await repoWith(a.dir, { '.npmrc': `//registry.npmjs.org/:_authToken=${FAKE.genericValue}\n` });
    const bad = await run(a.dir, a.ctx, ENV_TRACKED);
    expect(bad.outcome).toBe('fail');
    expect(bad.observed).toContain('.npmrc');
    expect(JSON.stringify(bad) + JSON.stringify(await evidenceOf(a.dir, bad))).not.toContain(FAKE.genericValue);

    const b = await makeCtx();
    await repoWith(b.dir, { '.npmrc': '//registry.npmjs.org/:_authToken=${NPM_TOKEN}\nsave-exact=true\n' });
    expect((await run(b.dir, b.ctx, ENV_TRACKED)).outcome).toBe('pass');
  });

  it('is unverifiable, not a pass, when an .npmrc is too large to read', async () => {
    const { ctx, dir } = await makeCtx({}, { code: { max_file_bytes: 50 } });
    await repoWith(dir, { '.npmrc': `registry=https://registry.npmjs.org/\n${'# padding\n'.repeat(20)}` });
    const out = await run(dir, ctx, ENV_TRACKED);
    expect(out.outcome).toBe('unverifiable');
    expect(out.observed).toContain('.npmrc');
  });

  it('honours code.exclude', async () => {
    const { ctx, dir } = await makeCtx({}, { code: { exclude: ['test/fixtures/'] } });
    await repoWith(dir, { 'test/fixtures/dev.pem': 'public certificate\n', 'a.ts': 'x\n' });
    expect((await run(dir, ctx, ENV_TRACKED)).outcome).toBe('pass');
  });

  it('a project directory below the repository root only sees its own files', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { '.env': 'A=1\n', 'app/ok.ts': 'x\n' });
    const sub = path.join(dir, 'app');
    await mkdir(path.join(sub, '.secagent'), { recursive: true });
    expect((await run(sub, ctx, ENV_TRACKED)).outcome).toBe('pass');
  });

  it('ignores anything under .secagent', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { '.secagent/.env': 'A=1\n', 'a.ts': 'x\n' });
    expect((await run(dir, ctx, ENV_TRACKED)).outcome).toBe('pass');
  });
});

describe('code_secrets env_not_ignored', () => {
  it('fails on an untracked .env that nothing ignores, and says one `git add .` would commit it', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { 'a.ts': 'x\n' });
    await writeFiles(dir, { '.env': `TOKEN=${FAKE.githubToken}\n` });
    const out = await run(dir, ctx, ENV_NOT_IGNORED);
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain('.env (environment file)');
    expect(out.observed).toContain('git add');
    expect(out.observed).toContain('.gitignore');
    const blob = JSON.stringify(out) + JSON.stringify(await evidenceOf(dir, out));
    expect(blob).not.toContain(FAKE.githubToken);
  });

  it('passes when .gitignore covers the file', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { '.gitignore': '.env*\n!.env.example\n', 'a.ts': 'x\n', '.env.example': 'A=\n' });
    await writeFiles(dir, { '.env': 'A=1\n', '.env.production': 'A=2\n' });
    const out = await run(dir, ctx, ENV_NOT_IGNORED);
    expect(out.outcome).toBe('pass');
  });

  it('passes when the file sits in an ignored directory', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { '.gitignore': 'secrets/\n', 'a.ts': 'x\n' });
    await writeFiles(dir, { 'secrets/server.key': 'k\n' });
    expect((await run(dir, ctx, ENV_NOT_IGNORED)).outcome).toBe('pass');
  });

  it('does not flag templates, nor a file that is already tracked (the other check owns that)', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { '.env': 'A=1\n', 'a.ts': 'x\n' });
    await writeFiles(dir, { '.env.example': 'A=\n' });
    expect((await run(dir, ctx, ENV_NOT_IGNORED)).outcome).toBe('pass');
  });

  it.each(['server.pem', 'keys/id_rsa', 'credentials.json', 'infra/terraform.tfstate', '.aws/credentials'])('fails on an unignored %s', async (name) => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { 'a.ts': 'x\n' });
    await writeFiles(dir, { [name]: 'x\n' });
    expect((await run(dir, ctx, ENV_NOT_IGNORED)).outcome).toBe('fail');
  });

  it('checks an untracked .npmrc for a literal token before flagging it', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { 'a.ts': 'x\n' });
    await writeFiles(dir, { '.npmrc': '//r.example.org/:_authToken=${NPM_TOKEN}\n' });
    expect((await run(dir, ctx, ENV_NOT_IGNORED)).outcome).toBe('pass');
    await writeFiles(dir, { '.npmrc': `//r.example.org/:_authToken=${FAKE.genericValue}\n` });
    expect((await run(dir, ctx, ENV_NOT_IGNORED)).outcome).toBe('fail');
  });

  it('honours code.exclude', async () => {
    const { ctx, dir } = await makeCtx({}, { code: { exclude: ['sandbox/'] } });
    await repoWith(dir, { 'a.ts': 'x\n' });
    await writeFiles(dir, { 'sandbox/.env': 'A=1\n' });
    expect((await run(dir, ctx, ENV_NOT_IGNORED)).outcome).toBe('pass');
  });
});

describe('code_secrets history', () => {
  it('fails on a secret that was committed and later removed, naming commit, file and pattern but not the value', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { 'config.ts': `export const k = '${FAKE.awsKeyId}';\n` });
    const added = git(dir, 'rev-parse', '--short=8', 'HEAD').trim();
    await writeFiles(dir, { 'config.ts': 'export const k = process.env.K;\n' });
    commitAll(dir, 'use the environment');

    expect((await run(dir, ctx)).outcome).toBe('pass'); // the working tree is clean: only history remembers
    const out = await run(dir, ctx, HISTORY);
    expect(out.outcome).toBe('fail');
    expect(out.observed).toContain(`config.ts aws-access-key-id [${fingerprint(FAKE.awsKeyId)}] added in ${added}`);
    expect(out.observed).toContain('rotate');
    expect(out.observed).toContain('does not remove it from history');
    const blob = JSON.stringify(out) + JSON.stringify(await evidenceOf(dir, out));
    expect(blob).not.toContain(FAKE.awsKeyId);
    const ev = await evidenceOf(dir, out);
    expect(ev.data.commits_scanned).toBe(2);
    expect(ev.data.hits).toEqual([
      expect.objectContaining({ path: 'config.ts', pattern: 'aws-access-key-id', fingerprint: fingerprint(FAKE.awsKeyId), line: 1, commit: expect.stringMatching(/^[0-9a-f]{40}$/) }),
    ]);
  });

  it('passes on a clean history and says how much it read', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { 'a.ts': 'x\n' });
    await writeFiles(dir, { 'b.ts': 'y\n' });
    commitAll(dir, 'second');
    const out = await run(dir, ctx, HISTORY);
    expect(out.outcome).toBe('pass');
    expect(out.observed).toContain('2 commit(s)');
  });

  it('passes on a repository with no commits', async () => {
    const { ctx, dir } = await makeCtx();
    gitInit(dir);
    expect((await run(dir, ctx, HISTORY)).outcome).toBe('pass');
  });

  it('reports a secret added in several commits once, at the earliest', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { 'a.ts': `${FAKE.githubToken}\n` });
    const first = git(dir, 'rev-parse', '--short=8', 'HEAD').trim();
    await writeFiles(dir, { 'a.ts': 'gone\n' });
    commitAll(dir, 'remove');
    await writeFiles(dir, { 'a.ts': `${FAKE.githubToken}\n` });
    commitAll(dir, 're-add');
    const out = await run(dir, ctx, HISTORY);
    expect(out.outcome).toBe('fail');
    expect((await evidenceOf(dir, out)).data.hits).toHaveLength(1);
    expect(out.observed).toContain(`added in ${first}`);
    expect(out.observed).toContain('1 secret(s)');
  });

  it('does not run the generic heuristic over history', async () => {
    const { ctx, dir } = await makeCtx();
    await repoWith(dir, { 'a.ts': `${PLANTED_LINES['generic-secret-assignment']}\n` });
    expect((await run(dir, ctx, HISTORY)).outcome).toBe('pass');
  });

  it('honours code.exclude', async () => {
    const { ctx, dir } = await makeCtx({}, { code: { exclude: ['fixtures/'] } });
    await repoWith(dir, { 'fixtures/leak.txt': `${FAKE.awsKeyId}\n`, 'a.ts': 'x\n' });
    expect((await run(dir, ctx, HISTORY)).outcome).toBe('pass');
  });

  it('is unverifiable, not a pass, when code.history is false', async () => {
    const { ctx, dir } = await makeCtx({}, { code: { history: false } });
    await repoWith(dir, { 'a.ts': `${FAKE.awsKeyId}\n` });
    const out = await runLikeRunner(dir, ctx, HISTORY);
    expect(out.outcome).toBe('unverifiable');
    expect(out.observed).toContain('code.history');
  });

  describe('limits', () => {
    async function repoOf(n: number, first: Record<string, string> = {}) {
      const made = await makeCtx();
      gitInit(made.dir);
      await writeFiles(made.dir, { 'f.txt': '0\n', ...first });
      commitAll(made.dir, 'c0');
      for (let i = 1; i < n; i += 1) {
        await writeFiles(made.dir, { [`f${i}.txt`]: `${i}\n` });
        commitAll(made.dir, `c${i}`);
      }
      return made;
    }

    it('is unverifiable when the commit limit cut the log short and nothing was found', async () => {
      const { ctx, dir } = await repoOf(4);
      const out = await run(dir, ctx, { rule: 'history', max_commits: 2 });
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('newest 2 commit(s)');
      expect(out.observed).toContain('does not mean');
    });

    it('is unverifiable when the diff-size limit cut the log short', async () => {
      const { ctx, dir } = await repoOf(1, { 'big.txt': 'filler line of text\n'.repeat(2000) });
      const out = await run(dir, ctx, { rule: 'history', max_diff_bytes: 1000 });
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('1000 bytes');
    });

    it('is unverifiable when the time limit cut the log short', async () => {
      const { ctx, dir } = await repoOf(3);
      await slowGitLog();
      const out = await run(dir, ctx, { rule: 'history', timeout_ms: 100 });
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('time limit');
    });

    it('still fails on what it found before the limit, and says the rest was not read', async () => {
      const { ctx, dir } = await repoOf(2);
      await writeFiles(dir, { 'leak.txt': `${FAKE.awsKeyId}\n` });
      commitAll(dir, 'newest commit leaks');
      const out = await run(dir, ctx, { rule: 'history', max_commits: 2 });
      expect(out.outcome).toBe('fail');
      expect(out.observed).toContain('leak.txt aws-access-key-id');
      expect(out.observed).toContain('Not all history was read');
    });

    it('does not let a cut-off hide an older secret behind a pass', async () => {
      const { ctx, dir } = await repoOf(1, { 'leak.txt': `${FAKE.awsKeyId}\n` });
      await writeFiles(dir, { 'g.txt': 'g\n' });
      commitAll(dir, 'c1');
      await writeFiles(dir, { 'h.txt': 'h\n' });
      commitAll(dir, 'c2');
      expect((await run(dir, ctx, { rule: 'history', max_commits: 3 })).outcome).toBe('fail');
      expect((await run(dir, ctx, { rule: 'history', max_commits: 2 })).outcome).toBe('unverifiable');
    });

    it('is unverifiable in a shallow clone: older commits are missing', async () => {
      const origin = await tempDir();
      await repoWith(origin, { 'a.txt': 'one\n' });
      await writeFiles(origin, { 'a.txt': 'two\n' });
      commitAll(origin, 'second');
      const { ctx, dir } = await makeCtx();
      const clone = path.join(dir, 'clone');
      git(dir, 'clone', '-q', '--depth', '1', `file://${origin}`, clone);
      await mkdir(path.join(clone, '.secagent'), { recursive: true });
      const out = await run(clone, ctx, HISTORY);
      expect(out.outcome).toBe('unverifiable');
      expect(out.observed).toContain('shallow');
    });
  });
});
