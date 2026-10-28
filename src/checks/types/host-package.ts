import path from 'node:path';
import { z } from 'zod';
import { distroOf } from '../../advisories/distro.js';
import { cveIdsOf, fixedVersionFor, ubuntuPriority } from '../../advisories/osv.js';
import type { Advisories, PackageQuery } from '../../advisories/types.js';
import { aptListsEmpty, classifyOrigin } from '../../host/origin.js';
import type { HostSnapshot } from '../../host/snapshot.js';
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

/**
 * Source packages to check against distro advisories, one per source at its highest installed version.
 * Third-party and locally installed packages are skipped, unless apt lists are empty and origins can't be known.
 */
export function distroSources(snap: HostSnapshot, codename: string): PackageQuery[] {
  const listsEmpty = aptListsEmpty(snap.origins);
  const best = new Map<string, string>();
  for (const pkg of snap.packages) {
    const kind = classifyOrigin(snap.origins[pkg.name], codename).kind;
    if (!listsEmpty && (kind === 'third_party' || kind === 'local')) continue;
    const current = best.get(pkg.source);
    if (current === undefined || compareDebVersions(pkg.source_version, current) > 0) best.set(pkg.source, pkg.source_version);
  }
  return [...best].map(([name, version]) => ({ name, version }));
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
  } catch {
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
      const evidence_id = await ctx.evidence.put('snapshot', name, 'reboot-required state', { ...base, excerpt: snapshot.reboot });
      if (!snapshot.reboot.required) return { outcome: 'pass', observed: 'no reboot pending', evidence_id };
      const pkgs = snapshot.reboot.packages.join(', ') || 'unspecified';
      return { outcome: 'fail', observed: `a reboot is pending (packages: ${pkgs})`, evidence_id };
    }

    if (p.assert === 'third_party') {
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
        if (o.kind === 'third_party') items.push({ package: pkg.name, version: pkg.version, origin: o.repo ?? 'unknown repository' });
        if (o.kind === 'local') items.push({ package: pkg.name, version: pkg.version, origin: 'installed locally, not from any configured repository' });
      }
      const evidence_id = await ctx.evidence.put('snapshot', name, `package origins (${items.length} non-distro)`, { ...base, excerpt: items });
      if (items.length === 0) return { outcome: 'pass', observed: `all ${seen.size} packages come from ${osName} repositories`, evidence_id };
      const listed = items.slice(0, p.max_listed).map((i) => `${i.package} ${i.version} (${i.origin})`);
      const more = items.length > p.max_listed ? `, and ${items.length - p.max_listed} more` : '';
      return {
        outcome: 'fail',
        observed: `${items.length} package(s) are not from ${osName} repositories, so distro security updates and unattended-upgrades do not cover them: ${listed.join('; ')}${more}`,
        evidence_id,
        details: { third_party: items },
      };
    }

    const distro = distroOf(snapshot.os);
    if (!distro) throw new ObservationError('UNSUPPORTED_DISTRO', `Package advisories are checked for Ubuntu and Debian only; this host runs "${osName}".`);
    if (snapshot.packages.length === 0) throw new ObservationError('NO_PACKAGES', 'The snapshot lists no installed packages (dpkg-query was unavailable).');
    const sources = distroSources(snapshot, distro.codename);
    const { fixable, unfixed, kev_available } = await findFixable(ctx.advisories, distro.ecosystem, sources);
    const evidence_id = await ctx.evidence.put('advisory', name, `${sources.length} packages checked against ${distro.ecosystem}`, {
      ...base,
      ecosystem: distro.ecosystem,
      checked: sources.length,
      fixable,
      unfixed,
      kev_available,
    });
    const kevNote = kev_available ? '' : '; CISA KEV was unavailable, so known-exploited CVEs were not escalated';
    if (fixable.length === 0) {
      const unfixedNote = unfixed > 0 ? `; ${unfixed} advisories have no released fix yet` : '';
      return {
        outcome: 'pass',
        observed: `${sources.length} distro source packages checked against ${distro.ecosystem} advisories; no security fixes pending${unfixedNote}${kevNote}`,
        evidence_id,
      };
    }
    const severity = maxSeverity(fixable.flatMap((f) => f.advisories.map((a) => a.severity)));
    const more = fixable.length > p.max_listed ? `; and ${fixable.length - p.max_listed} more` : '';
    return {
      outcome: 'fail',
      severity,
      observed: `${fixable.length} package(s) have security fixes not installed: ${fixable.slice(0, p.max_listed).map(describeFixable).join('; ')}${more}${kevNote}`,
      evidence_id,
      details: { fixable },
    };
  },
};
