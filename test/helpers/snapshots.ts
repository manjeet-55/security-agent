import { readFileSync } from 'node:fs';
import path from 'node:path';
import { decodeSnapshot, type HostSnapshot, type SnapshotEnvelope } from '../../src/host/snapshot.js';
import type { SnapshotReader } from '../../src/host/store.js';

const DIR = path.join(import.meta.dirname, '..', 'fixtures', 'collector');
export type FixtureName = 'ubuntu-24-04' | 'ubuntu-22-04' | 'debian-12';

export function fixtureEnvelope(name: FixtureName): SnapshotEnvelope {
  return JSON.parse(readFileSync(path.join(DIR, `${name}.json`), 'utf8')) as SnapshotEnvelope;
}

export function fixtureSnapshot(name: FixtureName): HostSnapshot {
  return decodeSnapshot(fixtureEnvelope(name));
}

export function sectionOf(env: SnapshotEnvelope, name: string): string {
  const s = env.sections[name];
  return s ? Buffer.from(s.b64, 'base64').toString('utf8') : '';
}

/** A copy of the envelope with one section replaced. */
export function withSection(env: SnapshotEnvelope, name: string, text: string, rc = 0): SnapshotEnvelope {
  return { ...env, sections: { ...env.sections, [name]: { rc, b64: Buffer.from(text, 'utf8').toString('base64') } } };
}

/** A copy where every binary built from `source` reports the given version. */
export function withSourceVersion(env: SnapshotEnvelope, source: string, version: string): SnapshotEnvelope {
  const lines = sectionOf(env, 'packages')
    .split('\n')
    .map((line) => {
      const cols = line.split('\t');
      if (cols[3] === source) {
        cols[2] = version;
        cols[4] = version;
      }
      return cols.join('\t');
    });
  return withSection(env, 'packages', lines.join('\n'));
}

/**
 * Every openssh-source binary reports `version` and is served only from `url` (suite noble/main), as a vendor build
 * from a repository that reuses the distro codename. Later apt-cache blocks override earlier ones.
 */
export function withVendorOpenssh(env: SnapshotEnvelope, url: string, version = '1:9.7p1-1~vendor1'): SnapshotEnvelope {
  let policy = sectionOf(withSourceVersion(env, 'openssh', version), 'apt_policy');
  for (const bin of ['openssh-client', 'openssh-server', 'openssh-sftp-server']) {
    policy += `\n${bin}:\n  Installed: ${version}\n  Candidate: ${version}\n  Version table:\n *** ${version} 500\n        500 ${url} noble/main amd64 Packages\n        100 /var/lib/dpkg/status\n`;
  }
  return withSection(withSourceVersion(env, 'openssh', version), 'apt_policy', policy);
}

/** A SnapshotReader serving one snapshot (or none) for every host. Store is defined in Task 6; only its type is used here. */
export function readerFor(snapshot: HostSnapshot | undefined, file = '/fixtures/20261028T143146Z.json'): SnapshotReader {
  return { latest: async () => (snapshot ? { snapshot, file } : undefined) };
}
