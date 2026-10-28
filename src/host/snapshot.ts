import { z } from 'zod';
import { ObservationError } from '../checks/errors.js';
import {
  parseAptPolicy,
  parseAutoUpgrades,
  parseListening,
  parseOsRelease,
  parsePackages,
  parseReboot,
  parseSshdT,
  type InstalledPackage,
  type ListeningSocket,
  type OsRelease,
  type PackageOrigin,
} from './parse.js';

export const SnapshotEnvelopeSchema = z.object({
  schema: z.literal(1),
  collector: z.string().min(1),
  collected_at: z.iso.datetime(),
  sections: z.record(z.string(), z.object({ rc: z.number().int(), b64: z.string() })),
});
export type SnapshotEnvelope = z.infer<typeof SnapshotEnvelopeSchema>;

export type SectionState<T> = { state: 'ok'; value: T } | { state: 'absent'; reason: string } | { state: 'error'; reason: string };

export interface HostSnapshot {
  collected_at: string;
  is_root: boolean;
  os: OsRelease;
  kernel: string;
  /** Empty when dpkg is unavailable (non-Debian host). */
  packages: InstalledPackage[];
  /** Keyed by binary package name without arch. */
  origins: Record<string, PackageOrigin>;
  auto_upgrades: { enabled: boolean; installed: boolean };
  reboot: { required: boolean; packages: string[] };
  sshd: SectionState<Record<string, string>>;
  /** Redacted `nginx -T` output. */
  nginx: SectionState<string>;
  listening: SectionState<ListeningSocket[]>;
}

function section(env: SnapshotEnvelope, name: string): { rc: number; text: string } | undefined {
  const s = env.sections[name];
  return s ? { rc: s.rc, text: Buffer.from(s.b64, 'base64').toString('utf8') } : undefined;
}

/** rc 0 = ok; rc 127 (shell "not found") = the tool isn't installed; anything else = couldn't read it (often: not run as root). */
function stateOf<T>(s: { rc: number; text: string } | undefined, parse: (text: string) => T): SectionState<T> {
  if (!s) return { state: 'error', reason: 'section missing from snapshot' };
  if (s.rc === 0) return { state: 'ok', value: parse(s.text) };
  const reason = (s.text.split('\n').find((l) => l.trim() !== '') ?? `exit code ${s.rc}`).trim();
  return s.rc === 127 ? { state: 'absent', reason } : { state: 'error', reason };
}

export function decodeSnapshot(raw: unknown): HostSnapshot {
  const parsed = SnapshotEnvelopeSchema.safeParse(raw);
  if (!parsed.success) {
    const issues = parsed.error.issues.map((i) => `${i.path.join('.') || '(root)'}: ${i.message}`).join('; ');
    throw new ObservationError('SNAPSHOT_INVALID', `Not a secagent collector snapshot: ${issues}`);
  }
  const env = parsed.data;
  const osRelease = section(env, 'os_release');
  if (!osRelease || osRelease.rc !== 0) throw new ObservationError('SNAPSHOT_INVALID', 'Snapshot has no readable /etc/os-release section.');
  const text = (name: string) => {
    const s = section(env, name);
    return s && s.rc === 0 ? s.text : '';
  };
  return {
    collected_at: env.collected_at,
    is_root: text('uid').trim() === '0',
    os: parseOsRelease(osRelease.text),
    kernel: text('kernel').trim(),
    packages: parsePackages(text('packages')),
    origins: parseAptPolicy(text('apt_policy')),
    auto_upgrades: parseAutoUpgrades(section(env, 'auto_upgrades')?.text ?? ''),
    reboot: parseReboot(text('reboot')),
    sshd: stateOf(section(env, 'sshd'), parseSshdT),
    nginx: stateOf(section(env, 'nginx'), (t) => t),
    listening: stateOf(section(env, 'listening'), parseListening),
  };
}
