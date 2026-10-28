import path from 'node:path';
import { distroOf } from '../advisories/distro.js';
import { fixedVersionFor } from '../advisories/osv.js';
import type { Advisories } from '../advisories/types.js';
import type { EvidenceStore } from '../evidence/store.js';
import type { HostSnapshot } from '../host/snapshot.js';
import type { SnapshotReader } from '../host/store.js';
import type { Host } from '../project/schema.js';
import { compareDebVersions } from '../util/debver.js';

/** In precedence order: when several packages are involved, the first verdict present wins. */
export const CLAIM_VERDICTS = ['vulnerable', 'no_fix_available', 'unverifiable', 'fixed_in_installed', 'not_affected'] as const;
export type ClaimVerdict = (typeof CLAIM_VERDICTS)[number];

export interface PackageVerdict {
  package: string;
  installed?: string;
  distro_status: string;
  fixed?: string;
  verdict: ClaimVerdict;
  note: string;
}

export interface ClaimResult {
  cve: string;
  host: string;
  verdict: ClaimVerdict;
  reason: string;
  packages: PackageVerdict[];
  /** `null` when the CISA KEV catalog was unavailable. */
  kev: boolean | null;
  source_url: string;
  snapshot: string;
  evidence_id: string;
}

export interface ClaimDeps {
  host: Host;
  snapshots: SnapshotReader;
  advisories: Advisories;
  evidence: EvidenceStore;
  now?: () => Date;
}

const NOT_AFFECTED_STATUSES = new Set(['not-affected', 'DNE']);

function overall(packages: PackageVerdict[]): ClaimVerdict {
  return CLAIM_VERDICTS.find((v) => packages.some((p) => p.verdict === v)) ?? 'unverifiable';
}

function compareInstalled(pkg: string, installed: string, fixed: string, status: string): PackageVerdict {
  const ok = compareDebVersions(installed, fixed) >= 0;
  return {
    package: pkg,
    installed,
    distro_status: status,
    fixed,
    verdict: ok ? 'fixed_in_installed' : 'vulnerable',
    note: ok ? `installed ${installed} >= fixed ${fixed}` : `installed ${installed} < fixed ${fixed}`,
  };
}

/**
 * Source package → lowest installed source version. The lowest is the conservative choice: an older binary from the same
 * source must not be hidden by a newer one.
 */
function installedSources(snap: HostSnapshot): Map<string, string> {
  const map = new Map<string, string>();
  for (const p of snap.packages) {
    const cur = map.get(p.source);
    if (cur === undefined || compareDebVersions(p.source_version, cur) < 0) map.set(p.source, p.source_version);
  }
  return map;
}

/** A binary package name maps to its source; anything else is taken as a source name. */
function sourceFilter(snap: HostSnapshot, pkg: string | undefined): string | undefined {
  if (!pkg) return undefined;
  return snap.packages.find((p) => p.name === pkg)?.source ?? pkg;
}

interface Judgement {
  packages: PackageVerdict[];
  reason: string;
  source_url: string;
  /** The verdict when no installed package could be judged. */
  whenEmpty: ClaimVerdict;
}

async function judge(snap: HostSnapshot, cve: string, advisories: Advisories, only: string | undefined): Promise<Judgement> {
  const distro = distroOf(snap.os);
  if (!distro) {
    const os = snap.os.pretty_name || snap.os.id;
    return { packages: [], reason: `Only Ubuntu and Debian hosts can be verified; this host runs "${os}".`, source_url: '', whenEmpty: 'unverifiable' };
  }
  const installed = installedSources(snap);

  if (distro.family === 'ubuntu') {
    const source_url = `https://ubuntu.com/security/${cve}`;
    const record = await advisories.ubuntu.cve(cve);
    if (!record) return { packages: [], reason: `Ubuntu has no record of ${cve}.`, source_url, whenEmpty: 'unverifiable' };
    if (record.packages.length === 0) return { packages: [], reason: `Ubuntu's record for ${cve} lists no packages.`, source_url, whenEmpty: 'unverifiable' };
    const tracked = record.packages.filter((p) => only === undefined || p.name === only);
    if (only !== undefined && tracked.length === 0) {
      const all = record.packages.map((p) => p.name).join(', ') || 'none';
      return {
        packages: [],
        reason: `Ubuntu for ${cve} does not track package "${only}" (tracked: ${all}).`,
        source_url,
        whenEmpty: 'unverifiable',
      };
    }
    const packages: PackageVerdict[] = [];
    for (const p of tracked) {
      const version = installed.get(p.name);
      if (version === undefined) continue;
      const s = p.statuses.find((x) => x.release_codename === distro.codename);
      if (!s) {
        packages.push({ package: p.name, installed: version, distro_status: 'unknown', verdict: 'unverifiable', note: `Ubuntu lists no status for ${distro.codename}` });
      } else if (s.status === 'released' && s.description) {
        packages.push(compareInstalled(p.name, version, s.description, s.status));
      } else if (NOT_AFFECTED_STATUSES.has(s.status)) {
        packages.push({ package: p.name, installed: version, distro_status: s.status, verdict: 'not_affected', note: s.description || `Ubuntu: ${s.status}` });
      } else {
        packages.push({ package: p.name, installed: version, distro_status: s.status, verdict: 'no_fix_available', note: `Ubuntu status "${s.status}"${s.description ? ` (${s.description})` : ''}` });
      }
    }
    if (packages.length === 0) {
      const names = tracked.map((p) => p.name).join(', ') || 'none';
      return { packages, reason: `none of the packages Ubuntu tracks for ${cve} (${names}) are installed on this host.`, source_url, whenEmpty: 'not_affected' };
    }
    return { packages, reason: `Ubuntu ${distro.codename} status for ${cve}.`, source_url, whenEmpty: 'unverifiable' };
  }

  const source_url = `https://security-tracker.debian.org/tracker/${cve}`;
  const record = await advisories.osv.vuln(`DEBIAN-${cve}`);
  if (!record) return { packages: [], reason: `The Debian security tracker (via OSV) has no record of ${cve}.`, source_url, whenEmpty: 'unverifiable' };
  if ((record.affected ?? []).length === 0) {
    return { packages: [], reason: `The Debian record for ${cve} lists no packages.`, source_url, whenEmpty: 'unverifiable' };
  }
  const entries = (record.affected ?? []).filter((a) => only === undefined || a.package.name === only);
  if (only !== undefined && entries.length === 0) {
    const all = [...new Set((record.affected ?? []).map((a) => a.package.name))].join(', ') || 'none';
    return {
      packages: [],
      reason: `The Debian record for ${cve} does not track package "${only}" (tracked: ${all}).`,
      source_url,
      whenEmpty: 'unverifiable',
    };
  }
  const forRelease = entries.filter((a) => a.package.ecosystem === distro.ecosystem);
  const packages: PackageVerdict[] = [];
  for (const a of forRelease) {
    const version = installed.get(a.package.name);
    if (version === undefined) continue;
    const fixed = fixedVersionFor(record, distro.ecosystem, a.package.name);
    packages.push(
      fixed
        ? compareInstalled(a.package.name, version, fixed, 'fixed')
        : { package: a.package.name, installed: version, distro_status: 'open', verdict: 'no_fix_available', note: `no fixed version for ${distro.ecosystem}` },
    );
  }
  if (packages.length > 0) return { packages, reason: `${distro.ecosystem} status for ${cve}.`, source_url, whenEmpty: 'unverifiable' };
  if (entries.some((a) => installed.has(a.package.name))) {
    return {
      packages,
      reason: `The Debian record for ${cve} has no entry for ${distro.ecosystem}, so this release can't be judged.`,
      source_url,
      whenEmpty: 'unverifiable',
    };
  }
  const names = [...new Set(entries.map((a) => a.package.name))].join(', ') || 'none';
  return { packages, reason: `none of the packages Debian tracks for ${cve} (${names}) are installed on this host.`, source_url, whenEmpty: 'not_affected' };
}

/** Deterministic verdict on a third-party scanner's claim that `cve` affects `host` (spec §7.1). */
export async function verifyClaim(deps: ClaimDeps, claim: { cve: string; package?: string }): Promise<ClaimResult> {
  const cve = claim.cve.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(cve)) throw new Error(`Not a CVE id: ${claim.cve}`);
  const now = deps.now ?? (() => new Date());
  const stored = await deps.snapshots.latest(deps.host.name);

  let packages: PackageVerdict[] = [];
  let reason: string;
  let source_url = '';
  let snapshot = '';
  let verdict: ClaimVerdict = 'unverifiable';
  if (!stored) {
    reason = `No collector snapshot for host "${deps.host.name}"; run "secagent collector --host ${deps.host.name}" first.`;
  } else {
    snapshot = path.basename(stored.file);
    const judged = await judge(stored.snapshot, cve, deps.advisories, sourceFilter(stored.snapshot, claim.package));
    ({ packages, reason, source_url } = judged);
    verdict = packages.length > 0 ? overall(packages) : judged.whenEmpty;
    const ageDays = Math.floor((now().getTime() - Date.parse(stored.snapshot.collected_at)) / 86_400_000);
    if (ageDays > 7) reason += ` Note: the snapshot is ${ageDays} days old.`;
  }

  let kev: boolean | null = false;
  try {
    kev = (await deps.advisories.kev.catalog()).has(cve);
  } catch {
    kev = null;
    reason += ' (CISA KEV was unavailable.)';
  }

  const evidence_id = await deps.evidence.put('advisory', deps.host.name, `verify_claim ${cve}: ${verdict}`, {
    cve,
    host: deps.host.name,
    snapshot,
    verdict,
    reason,
    packages,
    kev,
    source_url,
  });
  return { cve, host: deps.host.name, verdict, reason, packages, kev, source_url, snapshot, evidence_id };
}
