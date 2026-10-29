import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../src/checks/errors.js';
import { SnapshotStore } from '../../src/host/store.js';
import { fixtureEnvelope } from '../helpers/snapshots.js';
import { FIXED_NOW } from '../helpers/ctx.js';
import { tempDir } from '../helpers/tmp.js';

describe('SnapshotStore', () => {
  it('stores a validated snapshot by collected_at and returns the newest', async () => {
    const dir = await tempDir();
    const store = new SnapshotStore(dir, () => FIXED_NOW);
    const older = { ...fixtureEnvelope('ubuntu-24-04'), collected_at: '2026-10-20T00:00:00Z' };
    await store.add('web-1', JSON.stringify(older));
    const added = await store.add('web-1', JSON.stringify(fixtureEnvelope('ubuntu-24-04')));
    expect(added.file).toBe(path.join(dir, '.secagent', 'hosts', 'web-1', '20261028T143146Z.json'));
    expect((await store.latest('web-1'))?.snapshot.collected_at).toBe('2026-10-28T14:31:46Z');
  });

  it('rejects non-JSON, non-snapshots and bad host names', async () => {
    const store = new SnapshotStore(await tempDir(), () => FIXED_NOW);
    await expect(store.add('web-1', 'not json')).rejects.toBeInstanceOf(ObservationError);
    await expect(store.add('web-1', '{"schema":1}')).rejects.toThrow(/Not a secagent collector snapshot/);
    await expect(store.add('../etc', JSON.stringify(fixtureEnvelope('debian-12')))).rejects.toThrow(/Invalid host name/);
  });

  it('rejects a collected_at more than an hour in the future', async () => {
    const store = new SnapshotStore(await tempDir(), () => new Date('2026-10-28T10:00:00Z'));
    await expect(store.add('web-1', JSON.stringify(fixtureEnvelope('ubuntu-24-04')))).rejects.toMatchObject({ code: 'SNAPSHOT_INVALID' });
    const ok = new SnapshotStore(await tempDir(), () => new Date('2026-10-28T14:00:00Z'));
    await expect(ok.add('web-1', JSON.stringify(fixtureEnvelope('ubuntu-24-04')))).resolves.toBeDefined();
  });

  describe('future-dated snapshot files', () => {
    const futureEnv = { ...fixtureEnvelope('ubuntu-24-04'), collected_at: '2026-12-30T00:00:00Z' };

    async function seed(dir: string): Promise<{ store: SnapshotStore; futureFile: string }> {
      const store = new SnapshotStore(dir, () => FIXED_NOW);
      const futureFile = path.join(dir, '.secagent', 'hosts', 'web-1', '20261230T000000Z.json');
      await mkdir(path.dirname(futureFile), { recursive: true });
      await writeFile(futureFile, JSON.stringify(futureEnv));
      return { store, futureFile };
    }

    it('are skipped in favour of an older valid snapshot', async () => {
      const dir = await tempDir();
      const { store } = await seed(dir);
      await store.add('web-1', JSON.stringify({ ...fixtureEnvelope('ubuntu-24-04'), collected_at: '2026-10-27T00:00:00Z' }));
      expect((await store.latest('web-1'))?.snapshot.collected_at).toBe('2026-10-27T00:00:00Z');
    });

    it('a snapshot up to an hour ahead is still returned', async () => {
      const dir = await tempDir();
      const store = new SnapshotStore(dir, () => new Date('2026-10-28T14:00:00Z'));
      await store.add('web-1', JSON.stringify(fixtureEnvelope('ubuntu-24-04')));
      expect((await store.latest('web-1'))?.snapshot.collected_at).toBe('2026-10-28T14:31:46Z');
    });

    it('throw SNAPSHOT_INVALID naming the file to delete when nothing else is stored', async () => {
      const { store, futureFile } = await seed(await tempDir());
      const err = await store.latest('web-1').catch((e: unknown) => e);
      expect(err).toBeInstanceOf(ObservationError);
      expect(err).toMatchObject({ code: 'SNAPSHOT_INVALID' });
      expect((err as Error).message).toContain(futureFile);
      expect((err as Error).message).toMatch(/delete/i);
    });
  });

  it('validates the host name when reading', async () => {
    await expect(new SnapshotStore(await tempDir(), () => FIXED_NOW).latest('../etc')).rejects.toThrow(/Invalid host name/);
  });

  it('skips unreadable files and returns undefined for unknown hosts', async () => {
    const dir = await tempDir();
    const store = new SnapshotStore(dir, () => FIXED_NOW);
    await store.add('web-1', JSON.stringify(fixtureEnvelope('debian-12')));
    await writeFile(path.join(dir, '.secagent', 'hosts', 'web-1', 'junk.json'), '{');
    expect((await store.latest('web-1'))?.snapshot.os.id).toBe('debian');
    expect(await store.latest('nope')).toBeUndefined();
  });
});
