import { compareDebVersions } from '../util/debver.js';
import type { PackageOrigin } from './parse.js';

export type OriginKind = 'distro' | 'third_party' | 'local' | 'unknown';

const DISTRO_COMPONENTS = new Set(['main', 'restricted', 'universe', 'multiverse', 'contrib', 'non-free', 'non-free-firmware']);
const LOCAL_STATUS = '/var/lib/dpkg/status';

/** A source line from a distro suite (codename or codename-updates/-security/...) and component, on any mirror; PPAs excluded. */
function isDistroRepo(source: string, codename: string): boolean {
  const [url = '', suiteComponent = ''] = source.split(/\s+/);
  const [suite = '', component = ''] = suiteComponent.split('/');
  let host: string;
  try {
    host = new URL(url).hostname;
  } catch {
    return false;
  }
  const distroSuite = codename !== '' && (suite === codename || suite.startsWith(`${codename}-`));
  return distroSuite && DISTRO_COMPONENTS.has(component) && !host.includes('launchpad');
}

/**
 * Where the installed version came from. It is distro when a distro repo carries it, or when it is known only to
 * dpkg but a distro repo offers a newer version (an outdated distro package whose old version left the index).
 * It is third-party when a non-distro repo carries it (nginx.org, docker, PPAs). Otherwise it was installed locally.
 */
export function classifyOrigin(origin: PackageOrigin | undefined, codename: string): { kind: OriginKind; repo?: string } {
  if (!origin) return { kind: 'unknown' };
  const repos = origin.sources.filter((s) => s !== LOCAL_STATUS);
  if (repos.length > 0) {
    const distro = repos.find((s) => isDistroRepo(s, codename));
    return distro ? { kind: 'distro', repo: distro } : { kind: 'third_party', repo: repos[0] };
  }
  for (const offered of origin.available) {
    const distro = offered.sources.find((s) => isDistroRepo(s, codename));
    if (distro && compareDebVersions(offered.version, origin.installed) > 0) return { kind: 'distro', repo: distro };
  }
  return { kind: 'local' };
}

/** True when no package lists any repository source for any version: apt lists were cleaned or never fetched, so origins can't be known. */
export function aptListsEmpty(origins: Record<string, PackageOrigin>): boolean {
  return !Object.values(origins).some((o) => [...o.sources, ...o.available.flatMap((v) => v.sources)].some((s) => s !== LOCAL_STATUS));
}
