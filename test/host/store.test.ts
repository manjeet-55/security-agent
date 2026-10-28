import { writeFile } from 'node:fs/promises';
import path from 'node:path';
import { describe, expect, it } from 'vitest';
import { ObservationError } from '../../src/checks/errors.js';
import { SnapshotStore } from '../../src/host/store.js';
import { fixtureEnvelope } from '../helpers/snapshots.js';
import { tempDir } from '../helpers/tmp.js';

describe('SnapshotStore', () => {
  it('stores a validated snapshot by collected_at and returns the newest', async () => {
    const dir = await tempDir();
    const store = new SnapshotStore(dir);
    const older = { ...fixtureEnvelope('ubuntu-24-04'), collected_at: '2026-10-20T00:00:00Z' };
    await store.add('web-1', JSON.stringify(older));
    const added = await store.add('web-1', JSON.stringify(fixtureEnvelope('ubuntu-24-04')));
    expect(added.file).toBe(path.join(dir, '.secagent', 'hosts', 'web-1', '20261028T143146Z.json'));
    expect((await store.latest('web-1'))?.snapshot.collected_at).toBe('2026-10-28T14:31:46Z');
  });

  it('rejects non-JSON, non-snapshots and bad host names', async () => {
    const store = new SnapshotStore(await tempDir());
    await expect(store.add('web-1', 'not json')).rejects.toBeInstanceOf(ObservationError);
    await expect(store.add('web-1', '{"schema":1}')).rejects.toThrow(/Not a secagent collector snapshot/);
    await expect(store.add('../etc', JSON.stringify(fixtureEnvelope('debian-12')))).rejects.toThrow(/Invalid host name/);
  });

  it('skips unreadable files and returns undefined for unknown hosts', async () => {
    const dir = await tempDir();
    const store = new SnapshotStore(dir);
    await store.add('web-1', JSON.stringify(fixtureEnvelope('debian-12')));
    await writeFile(path.join(dir, '.secagent', 'hosts', 'web-1', 'junk.json'), '{');
    expect((await store.latest('web-1'))?.snapshot.os.id).toBe('debian');
    expect(await store.latest('nope')).toBeUndefined();
  });
});
