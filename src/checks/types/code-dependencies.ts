import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { z } from 'zod';
import { parseNpmLockfile, type LockedPackage } from '../../code/lockfile.js';
import type { Severity } from '../../types.js';
import type { CheckType } from '../check-type.js';
import { CODE_SUBJECT_ID } from '../context.js';
import { ObservationError } from '../errors.js';

export const codeDependenciesParams = z.object({ ecosystem: z.literal('npm'), max_packages: z.number().int().min(1).default(5000) }).strict();
export type CodeDependenciesParams = z.infer<typeof codeDependenciesParams>;

const LOCKFILES = ['package-lock.json', 'npm-shrinkwrap.json'];
const SHOWN = 8;
/** Packages with advisories whose ids are fetched; the rest are counted. */
const DETAILED = 40;

async function readIfExists(file: string): Promise<string | undefined> {
  try {
    return await readFile(file, 'utf8');
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code === 'ENOENT') return undefined;
    throw e;
  }
}

/** GitHub advisories in OSV carry a severity word; anything CRITICAL raises the finding to critical. */
function severityOf(vulns: ReadonlyArray<{ database_specific?: { severity?: string } }>): Severity {
  return vulns.some((v) => v.database_specific?.severity?.toUpperCase() === 'CRITICAL') ? 'critical' : 'high';
}

export const codeDependenciesCheck: CheckType<CodeDependenciesParams> = {
  type: 'code_dependencies',
  supports: ['code'],
  params: codeDependenciesParams,
  async run(ctx, subject, p) {
    if (subject.kind !== 'code') throw new Error('code_dependencies runs on the project directory only');
    let lockName: string | undefined;
    let text: string | undefined;
    for (const name of LOCKFILES) {
      text = await readIfExists(path.join(subject.dir, name));
      if (text !== undefined) {
        lockName = name;
        break;
      }
    }
    if (text === undefined || !lockName) {
      if ((await readIfExists(path.join(subject.dir, 'package.json'))) === undefined) {
        const evidence_id = await ctx.evidence.put('code', CODE_SUBJECT_ID, 'no npm project', { lockfile: null });
        return { outcome: 'pass', observed: 'not an npm project (no package.json), so there are no npm dependencies to check', evidence_id };
      }
      throw new ObservationError('NO_LOCKFILE', 'package.json has no package-lock.json next to it, so the installed versions are unknown. Run npm install and commit package-lock.json.');
    }
    let packages: LockedPackage[];
    try {
      packages = parseNpmLockfile(text);
    } catch (e) {
      throw new ObservationError('LOCKFILE_INVALID', `${lockName} could not be read: ${e instanceof Error ? e.message : String(e)}.`);
    }
    if (packages.length > p.max_packages) {
      throw new ObservationError('TOO_MANY_PACKAGES', `${lockName} pins ${packages.length} packages, more than max_packages (${p.max_packages}); raise it in the check's params.`);
    }

    let affected: Set<string>;
    try {
      affected = await ctx.advisories.osv.affected('npm', packages);
    } catch (e) {
      throw new ObservationError('ADVISORIES_UNAVAILABLE', `The OSV advisory database could not be reached (${e instanceof Error ? e.message : String(e)}), so the dependencies were not checked.`);
    }
    const hits = packages.filter((pkg) => affected.has(pkg.name));
    const detailed: Array<LockedPackage & { advisories: string[]; severity: Severity }> = [];
    for (const pkg of hits.slice(0, DETAILED)) {
      try {
        const vulns = (await ctx.advisories.osv.vulnsFor('npm', pkg)) as Array<{ id: string; database_specific?: { severity?: string } }>;
        detailed.push({ ...pkg, advisories: vulns.map((v) => v.id).sort(), severity: severityOf(vulns) });
      } catch {
        detailed.push({ ...pkg, advisories: [], severity: 'high' });
      }
    }

    const evidence_id = await ctx.evidence.put('advisory', CODE_SUBJECT_ID, `${packages.length} npm package(s) from ${lockName} checked against OSV`, {
      lockfile: lockName,
      packages: packages.length,
      dev_packages: packages.filter((x) => x.dev).length,
      affected: detailed,
      affected_count: hits.length,
    });
    if (hits.length === 0) return { outcome: 'pass', observed: `none of the ${packages.length} npm package(s) in ${lockName} has a known advisory (OSV)`, evidence_id };
    const shown = detailed
      .slice(0, SHOWN)
      .map((d) => `${d.name}@${d.version}${d.dev ? ' (dev)' : ''}${d.advisories.length > 0 ? ` ${d.advisories.slice(0, 3).join(', ')}${d.advisories.length > 3 ? ', ...' : ''}` : ''}`)
      .join('; ');
    const more = hits.length > SHOWN ? `; and ${hits.length - SHOWN} more` : '';
    return {
      outcome: 'fail',
      severity: detailed.some((d) => d.severity === 'critical') ? 'critical' : 'high',
      observed: `${hits.length} of ${packages.length} npm package(s) have known advisories: ${shown}${more}. Run npm audit for the fixed versions.`,
      evidence_id,
      details: { affected: detailed.slice(0, 50), affected_count: hits.length },
    };
  },
};
