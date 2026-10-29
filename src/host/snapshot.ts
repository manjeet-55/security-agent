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
  /** Empty when dpkg is unavailable (non-Debian host); see `packages_error`. */
  packages: InstalledPackage[];
  /** Set when the packages section failed, is missing or listed no installed package: consumers must not treat `[]` as "nothing installed". */
  packages_error?: string;
  /** Keyed by binary package name without arch. */
  origins: Record<string, PackageOrigin>;
  /** True when the apt_policy section is missing or failed: `origins` is empty because it is unknown, not because nothing has an origin. */
  origins_unavailable?: boolean;
  auto_upgrades: { enabled: boolean; installed: boolean };
  reboot: { required: boolean; packages: string[] };
  /** Set unless the reboot section ran with rc 0 and reported "required" or "not-required". */
  reboot_error?: string;
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

/** The installed packages, or ObservationError('NO_PACKAGES') when the packages section is missing, failed or empty. */
export function requirePackages(snap: HostSnapshot): InstalledPackage[] {
  if (snap.packages_error !== undefined || snap.packages.length === 0) {
    throw new ObservationError('NO_PACKAGES', `The snapshot has no usable installed-package list (${snap.packages_error ?? 'no installed packages'}).`);
  }
  return snap.packages;
}

function packagesError(s: { rc: number; text: string } | undefined, count: number): string | undefined {
  if (!s) return 'packages section missing from snapshot';
  if (s.rc !== 0) return `dpkg-query failed (exit code ${s.rc})`;
  return count === 0 ? 'dpkg-query listed no installed packages' : undefined;
}

function rebootError(s: { rc: number; text: string } | undefined): string | undefined {
  if (!s) return 'reboot section missing from snapshot';
  if (s.rc !== 0) return `reboot check failed (exit code ${s.rc})`;
  const first = s.text.split('\n').find((l) => l.trim() !== '')?.trim();
  return first === 'required' || first === 'not-required' ? undefined : 'reboot check printed neither "required" nor "not-required"';
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
  const aptPolicy = section(env, 'apt_policy');
  const pkgSection = section(env, 'packages');
  const packages = parsePackages(text('packages'));
  const pkgError = packagesError(pkgSection, packages.length);
  const rebootErr = rebootError(section(env, 'reboot'));
  return {
    collected_at: env.collected_at,
    is_root: text('uid').trim() === '0',
    os: parseOsRelease(osRelease.text),
    kernel: text('kernel').trim(),
    packages,
    ...(pkgError !== undefined ? { packages_error: pkgError } : {}),
    origins: parseAptPolicy(text('apt_policy')),
    ...(aptPolicy === undefined || aptPolicy.rc !== 0 ? { origins_unavailable: true } : {}),
    auto_upgrades: parseAutoUpgrades(section(env, 'auto_upgrades')?.text ?? ''),
    reboot: parseReboot(text('reboot')),
    ...(rebootErr !== undefined ? { reboot_error: rebootErr } : {}),
    sshd: stateOf(section(env, 'sshd'), parseSshdT),
    nginx: stateOf(section(env, 'nginx'), (t) => t),
    listening: stateOf(section(env, 'listening'), parseListening),
  };
}
