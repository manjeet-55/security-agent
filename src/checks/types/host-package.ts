import path from 'node:path';
import { z } from 'zod';
import { distroOf } from '../../advisories/distro.js';
import { cveIdsOf, fixedVersionFor, ubuntuPriority } from '../../advisories/osv.js';
import type { Advisories, PackageQuery } from '../../advisories/types.js';
import { aptListsEmpty, classifyOrigin } from '../../host/origin.js';
import { describeDpkgState, isSettled, type InstalledPackage } from '../../host/parse.js';
import { requirePackages, type HostSnapshot } from '../../host/snapshot.js';
import { maxSeverity, SEVERITY_RANK, type Severity } from '../../types.js';
import { compareDebVersions } from '../../util/debver.js';
import type { CheckType } from '../check-type.js';
import { getSnapshot } from '../context.js';
import { ObservationError } from '../errors.js';

export const hostPackageParams = z.discriminatedUnion('assert', [
  z.object({ assert: z.literal('advisories'), max_listed: z.number().int().min(1).default(5) }),
  z.object({ assert: z.literal('third_party'), max_listed: z.number().int().min(1).default(10) }),
  z.object({ assert: z.literal('reboot') }),
]);
export type HostPackageParams = z.infer<typeof hostPackageParams>;

const PRIORITY: Record<string, Severity> = { critical: 'critical', high: 'high', medium: 'medium', low: 'low', negligible: 'info' };

export interface FixablePackage {
  package: string;
  installed: string;
  advisories: Array<{ id: string; cves: string[]; fixed: string; severity: Severity; kev: boolean }>;
}

/** The installed packages whose source `distroSources` checks: positively distro, or any when origins can't be known at all. */
function checkedPackages(snap: HostSnapshot, codename: string): InstalledPackage[] {
  const listsEmpty = aptListsEmpty(snap.origins);
  return snap.packages.filter((pkg) => listsEmpty || classifyOrigin(snap.origins[pkg.name], codename).kind === 'distro');
}

/**
 * Source packages to check against distro advisories, one per source at its lowest installed version
 * (the conservative choice: a lagging binary must not hide a pending fix).
 * Anything not positively identified as distro (third-party, local, origin unknown) is skipped, unless apt lists are empty
 * and origins can't be known at all.
 */
export function distroSources(snap: HostSnapshot, codename: string): PackageQuery[] {
  const best = new Map<string, string>();
  for (const pkg of checkedPackages(snap, codename)) {
    const current = best.get(pkg.source);
    if (current === undefined || compareDebVersions(pkg.source_version, current) < 0) best.set(pkg.source, pkg.source_version);
  }
  return [...best].map(([name, version]) => ({ name, version }));
}

/** How many distinct packages `distroSources` leaves out because they are not positively identified as distro (third-party, local, origin unknown). */
export function skippedSourceCount(snap: HostSnapshot, codename: string): number {
  if (aptListsEmpty(snap.origins)) return 0;
  const skipped = new Set<string>();
  for (const pkg of snap.packages) {
    if (classifyOrigin(snap.origins[pkg.name], codename).kind !== 'distro') skipped.add(pkg.name);
  }
  return skipped.size;
}

export async function findFixable(
  advisories: Advisories,
  ecosystem: string,
  sources: readonly PackageQuery[],
): Promise<{ fixable: FixablePackage[]; unfixed: number; kev_available: boolean }> {
  const affected = await advisories.osv.affected(ecosystem, sources);
  let kev = new Set<string>();
  let kev_available = true;
  try {
    kev = await advisories.kev.catalog();
  } catch (err) {
    if (!(err instanceof ObservationError)) throw err;
    kev_available = false;
  }
  const fixable: FixablePackage[] = [];
  let unfixed = 0;
  for (const q of sources.filter((s) => affected.has(s.name))) {
    const items: FixablePackage['advisories'] = [];
    for (const v of await advisories.osv.vulnsFor(ecosystem, q)) {
      const fixed = fixedVersionFor(v, ecosystem, q.name);
      if (!fixed) {
        unfixed += 1;
        continue;
      }
      if (compareDebVersions(q.version, fixed) >= 0) continue;
      const cves = cveIdsOf(v);
      const isKev = cves.some((c) => kev.has(c));
      items.push({ id: v.id, cves, fixed, severity: isKev ? 'critical' : (PRIORITY[ubuntuPriority(v) ?? ''] ?? 'medium'), kev: isKev });
    }
    if (items.length > 0) fixable.push({ package: q.name, installed: q.version, advisories: items });
  }
  return { fixable, unfixed, kev_available };
}

function describeFixable(f: FixablePackage): string {
  const sorted = [...f.advisories].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  const top = sorted[0];
  const head = top ? `${top.cves[0] ?? top.id} ${top.severity}${top.kev ? ' KEV' : ''} fixed in ${top.fixed}` : '';
  return `${f.package} ${f.installed} (${f.advisories.length}: ${head}${f.advisories.length > 1 ? ', ...' : ''})`;
}

export const hostPackageCheck: CheckType<HostPackageParams> = {
  type: 'host_package',
  supports: ['host'],
  params: hostPackageParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'host') throw new Error('host_package runs on hosts only');
    const { snapshot, file } = await getSnapshot(ctx, subject.host);
    const name = subject.host.name;
    const base = { snapshot: path.basename(file), collected_at: snapshot.collected_at };
    const osName = snapshot.os.pretty_name || snapshot.os.id;

    if (p.assert === 'reboot') {
      if (snapshot.reboot_error !== undefined) throw new ObservationError('REBOOT_UNREADABLE', `The reboot check could not be read: ${snapshot.reboot_error}.`);
      const evidence_id = await ctx.evidence.put('snapshot', name, 'reboot-required state', { ...base, excerpt: snapshot.reboot });
      if (!snapshot.reboot.required) return { outcome: 'pass', observed: 'no reboot pending', evidence_id };
      const pkgs = snapshot.reboot.packages.join(', ') || 'unspecified';
      return { outcome: 'fail', observed: `a reboot is pending (packages: ${pkgs})`, evidence_id };
    }

    if (p.assert === 'third_party') {
      requirePackages(snapshot);
      if (aptListsEmpty(snapshot.origins)) {
        throw new ObservationError(
          'APT_LISTS_EMPTY',
          'apt package lists are empty on this host (cleaned or never fetched), so package origins cannot be determined. Run "apt-get update" before the collector.',
        );
      }
      const seen = new Set<string>();
      const items: Array<{ package: string; version: string; origin: string }> = [];
      for (const pkg of snapshot.packages) {
        if (seen.has(pkg.name)) continue;
        seen.add(pkg.name);
        const o = classifyOrigin(snapshot.origins[pkg.name], snapshot.os.codename);
        if (o.kind === 'distro') continue;
        const origin =
          o.kind === 'third_party'
            ? (o.repo ?? 'unknown repository')
            : o.kind === 'local'
              ? 'installed locally, not from any configured repository'
              : `origin unknown${o.repo ? `: ${o.repo}` : ': no apt-cache entry'}`;
        items.push({ package: pkg.name, version: pkg.version, origin });
      }
      const evidence_id = await ctx.evidence.put('snapshot', name, `package origins (${items.length} non-distro)`, { ...base, excerpt: items });
      if (items.length === 0) return { outcome: 'pass', observed: `all ${seen.size} packages come from ${osName} repositories`, evidence_id };
      const listed = items.slice(0, p.max_listed).map((i) => `${i.package} ${i.version} (${i.origin})`);
      const more = items.length > p.max_listed ? `, and ${items.length - p.max_listed} more` : '';
      return {
        outcome: 'fail',
        observed: `${items.length} package(s) are not verifiably from ${osName} repositories, so distro security updates and unattended-upgrades may not cover them: ${listed.join('; ')}${more}`,
        evidence_id,
        details: { third_party: items },
      };
    }

    const distro = distroOf(snapshot.os);
    if (!distro) throw new ObservationError('UNSUPPORTED_DISTRO', `Package advisories are checked for Ubuntu and Debian only; this host runs "${osName}".`);
    requirePackages(snapshot);
    const sources = distroSources(snapshot, distro.codename);
    if (sources.length === 0) {
      throw new ObservationError(
        'NO_DISTRO_PACKAGES',
        `No installed package could be attributed to ${osName} repositories, so distro advisories could not be checked.`,
      );
    }
    const skipped = skippedSourceCount(snapshot, distro.codename);
    const { value: found, freshness: fresh } = await ctx.advisories.track(() => findFixable(ctx.advisories, distro.ecosystem, sources));
    const { fixable, unfixed, kev_available } = found;
    if (fixable.length === 0) {
      const unsettled = checkedPackages(snapshot, distro.codename).filter((pkg) => !isSettled(pkg));
      if (unsettled.length > 0) {
        const listed = unsettled.slice(0, 5).map((pkg) => `${pkg.name} ${describeDpkgState(pkg.state)}`);
        throw new ObservationError(
          'DPKG_STATE',
          `${unsettled.length} checked package(s) are not fully installed, so "no fixes pending" cannot be shown: ${listed.join('; ')}${unsettled.length > 5 ? '; ...' : ''}. Run dpkg --configure -a on the host and collect again.`,
        );
      }
    }
    const evidence_id = await ctx.evidence.put('advisory', name, `${sources.length} packages checked against ${distro.ecosystem}`, {
      ...base,
      ecosystem: distro.ecosystem,
      checked: sources.length,
      skipped_non_distro: skipped,
      fixable,
      unfixed,
      kev_available,
      ...(fresh ? { advisories_as_of: fresh.as_of, advisories_stale: fresh.stale } : {}),
    });
    const asOfNote = fresh ? `; advisory data as of ${fresh.as_of.slice(0, 10)}${fresh.stale ? ', STALE (cached copy; source unreachable)' : ''}` : '';
    const kevNote = kev_available ? '' : '; CISA KEV was unavailable, so known-exploited CVEs were not escalated';
    const skippedNote = skipped > 0 ? `; ${skipped} non-distro packages not checked (see host-package-third-party)` : '';
    if (fixable.length === 0) {
      const unfixedNote = unfixed > 0 ? `; ${unfixed} advisories have no released fix yet` : '';
      return {
        outcome: 'pass',
        observed: `${sources.length} distro source packages checked against ${distro.ecosystem} advisories; no security fixes pending${unfixedNote}${kevNote}${skippedNote}${asOfNote}`,
        evidence_id,
      };
    }
    const severity = maxSeverity(fixable.flatMap((f) => f.advisories.map((a) => a.severity)));
    const more = fixable.length > p.max_listed ? `; and ${fixable.length - p.max_listed} more` : '';
    return {
      outcome: 'fail',
      severity,
      observed: `${fixable.length} package(s) have security fixes not installed: ${fixable.slice(0, p.max_listed).map(describeFixable).join('; ')}${more}${kevNote}${skippedNote}${asOfNote}`,
      evidence_id,
      details: { fixable },
    };
  },
};
