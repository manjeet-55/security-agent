import type { HostSnapshot } from './snapshot.js';

export interface StoredSnapshot {
  snapshot: HostSnapshot;
  file: string;
}

export interface SnapshotReader {
  latest(host: string): Promise<StoredSnapshot | undefined>;
}
