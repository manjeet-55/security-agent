import type { PackageQuery } from '../advisories/types.js';

export interface LockedPackage extends PackageQuery {
  dev: boolean;
}

/**
 * The packages an npm lockfile pins (package-lock.json or npm-shrinkwrap.json, lockfileVersion 1, 2 or 3), one per name@version,
 * sorted. Linked workspace packages and entries without a version are skipped. Throws on anything that is not a lockfile.
 */
export function parseNpmLockfile(text: string): LockedPackage[] {
  const lock = JSON.parse(text) as {
    lockfileVersion?: number;
    packages?: Record<string, { version?: string; dev?: boolean; link?: boolean }>;
    dependencies?: Record<string, V1Dep>;
  };
  if (typeof lock !== 'object' || lock === null || typeof lock.lockfileVersion !== 'number') throw new Error('not an npm lockfile (no lockfileVersion)');
  const out = new Map<string, LockedPackage>();
  const add = (name: string, version: string | undefined, dev: boolean) => {
    if (!name || !version || version.startsWith('file:') || version.startsWith('link:')) return;
    const key = `${name}@${version}`;
    const have = out.get(key);
    out.set(key, { name, version, dev: have ? have.dev && dev : dev });
  };
  if (lock.packages) {
    for (const [p, entry] of Object.entries(lock.packages)) {
      if (p === '' || entry.link) continue;
      const at = p.lastIndexOf('node_modules/');
      if (at === -1) continue;
      add(p.slice(at + 'node_modules/'.length), entry.version, entry.dev === true);
    }
  } else if (lock.dependencies) {
    const walk = (deps: Record<string, V1Dep>) => {
      for (const [name, d] of Object.entries(deps)) {
        add(name, d.version, d.dev === true);
        if (d.dependencies) walk(d.dependencies);
      }
    };
    walk(lock.dependencies);
  }
  return [...out.values()].sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));
}

interface V1Dep {
  version?: string;
  dev?: boolean;
  dependencies?: Record<string, V1Dep>;
}
