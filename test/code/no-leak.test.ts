import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { main } from '../../src/cli.js';
import { PATTERN_IDS } from '../../src/code/patterns.js';
import { initProject } from '../../src/project/init.js';
import { scanNoAi } from '../../src/scan/no-ai.js';
import { commitAll, gitInit } from '../helpers/git.js';
import { FAKE, PLANTED_LINES } from '../helpers/secrets.js';
import { tempDir, writeFiles } from '../helpers/tmp.js';

afterEach(() => {
  vi.restoreAllMocks();
});

/** Every raw value a scan must never repeat, including the pieces of the ones that are built from parts. */
const RAW_SECRETS = [
  FAKE.awsKeyId,
  FAKE.privateKeyBody,
  FAKE.githubToken,
  FAKE.slackToken,
  FAKE.stripeLiveKey,
  FAKE.googleApiKey,
  FAKE.jwt,
  ...FAKE.jwt.split('.'),
  FAKE.urlPassword,
  FAKE.genericValue,
  `app_user:${FAKE.urlPassword}`,
];

function filesUnder(dir: string): string[] {
  return readdirSync(dir).flatMap((name) => {
    const full = path.join(dir, name);
    return statSync(full).isDirectory() ? filesUnder(full) : [full];
  });
}

/** Everything a user could see or a later run could read back: results, console output and each file written under .secagent/. */
function everythingWritten(dir: string, record: unknown, consoleLines: string[]): string {
  const files = filesUnder(path.join(dir, '.secagent')).map((f) => readFileSync(f, 'utf8'));
  return [JSON.stringify(record), ...consoleLines, ...files].join('\n');
}

async function plant(dir: string): Promise<void> {
  const leaks = Object.fromEntries(Object.entries(PLANTED_LINES).map(([id, line]) => [`src/${id}.ts`, `${line}\n${FAKE.privateKeyBody}\n`]));
  await writeFiles(dir, {
    ...leaks,
    '.env': `DB_PASSWORD=${FAKE.urlPassword}\nTOKEN=${FAKE.githubToken}\n`,
    'certs/server.key': `${FAKE.privateKeyHeader}\n${FAKE.privateKeyBody}\n-----END RSA PRIVATE KEY-----\n`,
    'old.ts': `export const k = '${FAKE.stripeLiveKey}';\n`,
  });
}

describe('a scan never repeats a secret it found', () => {
  it('in a git repository, across the working tree, tracked files and removed-from-history secrets', async () => {
    const dir = await tempDir();
    gitInit(dir);
    await plant(dir);
    commitAll(dir, 'leaky');
    await writeFiles(dir, { 'old.ts': 'export const k = process.env.K;\n' });
    commitAll(dir, 'stop leaking, too late');
    await initProject(dir, { scanLabel: 'test-net' });

    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    const error = vi.spyOn(console, 'error').mockImplementation(() => {});
    expect(await main(['scan', '--no-ai', '--dir', dir])).toBe(0);
    const printed = [...log.mock.calls, ...error.mock.calls].map((c) => c.join(' '));
    const record = await scanNoAi(dir, { now: () => new Date('2026-10-28T10:00:00.000Z') });

    // the scan really found things, or the assertions below prove nothing
    const found = record.findings.map((f) => f.id);
    expect(found).toEqual(expect.arrayContaining(['code-secrets-working-tree@code', 'code-env-files-tracked@code', 'code-secrets-history@code']));
    const evidence = filesUnder(path.join(dir, '.secagent', 'evidence')).map((f) => JSON.parse(readFileSync(f, 'utf8')));
    const treeHits = evidence.flatMap((e) => e.data?.hits ?? []) as Array<{ pattern: string; path?: string }>;
    for (const id of PATTERN_IDS) expect(treeHits.some((h) => h.pattern === id), `no ${id} hit in evidence`).toBe(true);
    expect(treeHits.some((h) => h.path === 'old.ts')).toBe(true);

    const everything = everythingWritten(dir, record, printed);
    for (const raw of RAW_SECRETS) expect(everything, `"${raw.slice(0, 6)}…" was written out`).not.toContain(raw);
  });

  it('in a plain directory, where only the working tree is scanned', async () => {
    const dir = await tempDir();
    await plant(dir);
    await initProject(dir, { scanLabel: 'test-net' });
    const log = vi.spyOn(console, 'log').mockImplementation(() => {});
    expect(await main(['scan', '--no-ai', '--dir', dir])).toBe(0);
    const record = await scanNoAi(dir, { now: () => new Date('2026-10-28T10:00:00.000Z') });
    expect(record.findings.some((f) => f.id === 'code-secrets-working-tree@code' && f.status === 'open')).toBe(true);
    const everything = everythingWritten(dir, record, log.mock.calls.map((c) => c.join(' ')));
    for (const raw of RAW_SECRETS) expect(everything, `"${raw.slice(0, 6)}…" was written out`).not.toContain(raw);
  });

  it('writes nothing outside .secagent', async () => {
    const dir = await tempDir();
    gitInit(dir);
    await plant(dir);
    commitAll(dir, 'leaky');
    await initProject(dir, { scanLabel: 'test-net' });
    const before = filesUnder(dir).filter((f) => !f.includes(`${path.sep}.secagent${path.sep}`) && !f.includes(`${path.sep}.git${path.sep}`));
    const contents = new Map(before.map((f) => [f, readFileSync(f, 'utf8')]));
    await scanNoAi(dir, { now: () => new Date('2026-10-28T10:00:00.000Z') });
    const after = filesUnder(dir).filter((f) => !f.includes(`${path.sep}.secagent${path.sep}`) && !f.includes(`${path.sep}.git${path.sep}`));
    expect(after.sort()).toEqual(before.sort());
    for (const [f, text] of contents) expect(readFileSync(f, 'utf8')).toBe(text);
  });
});
