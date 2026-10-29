import { compareDebVersions } from '../util/debver.js';
import type { PackageOrigin } from './parse.js';
import type { HostSnapshot } from './snapshot.js';

export type OriginKind = 'distro' | 'third_party' | 'local' | 'unknown';

const DISTRO_COMPONENTS = new Set(['main', 'restricted', 'universe', 'multiverse', 'contrib', 'non-free', 'non-free-firmware']);
const LOCAL_STATUS = '/var/lib/dpkg/status';

const DISTRO_HOST = /(^|\.)(ubuntu\.com|debian\.org)$/;

type RepoKind = 'distro' | 'unknown' | 'third_party';

const HOST_AND_PORT = /^([a-z0-9.-]+)(:\d+)?$/;
/** What may precede the last `@` of the authority: RFC 3986 userinfo characters, plus `@` itself (a password may contain one). */
const USERINFO = /^[a-z0-9._~%!$&'()*+,;=:@-]*$/i;

/**
 * The host of an apt source URL, read literally: the text between `://` and the next `/`, without any userinfo (up to the last
 * `@`), lowercased, with one trailing `.` (the absolute form of a name) dropped. `undefined` when that text is not a plain
 * host name with an optional port, or when the userinfo holds a character that cannot belong to it (`\`, `#`, `?`, `[`, ...).
 * A URL parser is deliberately not used: the WHATWG one reads a backslash as a slash, so `http://archive.ubuntu.com\.evil.example/`
 * would pass for archive.ubuntu.com although apt does not fetch from there.
 */
function repoHost(url: string): string | undefined {
  const start = url.indexOf('://');
  if (start < 0) return undefined;
  let authority = url.slice(start + 3);
  const end = authority.indexOf('/');
  if (end >= 0) authority = authority.slice(0, end);
  const at = authority.lastIndexOf('@');
  if (!USERINFO.test(authority.slice(0, Math.max(at, 0)))) return undefined;
  const host = HOST_AND_PORT.exec(authority.slice(at + 1).toLowerCase())?.[1];
  if (host === undefined) return undefined;
  return host.endsWith('.') ? host.slice(0, -1) : host;
}

/**
 * Classifies one apt source line ("<url> <suite>/<component> <arch> Packages").
 *
 * - `distro`: the host is ubuntu.com, debian.org or a subdomain, the suite is the host codename (or `codename-updates`,
 *   `-security`, ...) and the component is a distro component. The host is the only identity secagent can trust.
 * - `unknown`: the suite and component look like a distro's but the host is not a distro host. That is a third-party mirror
 *   or a vendor repo that reuses the codename and `main` (packagecloud, cloudsmith, mariadb, packages.sury.org, ...);
 *   a path ending in `/ubuntu` or `/debian` proves nothing, so no path is accepted. Treated as unverifiable until a
 *   trusted-mirror allowlist exists. A URL whose host cannot be read as a plain host name (`repoHost`) is also `unknown`.
 * - `third_party`: anything else (a different suite or component such as nginx.org `noble/nginx`, docker `noble/stable`,
 *   and PPAs on launchpad).
 */
function repoKind(source: string, codename: string, mirrors: readonly string[] = []): RepoKind {
  const [url = '', suiteComponent = ''] = source.split(/\s+/);
  const [suite = '', component = ''] = suiteComponent.split('/');
  const host = repoHost(url);
  if (host === undefined) return 'unknown';
  const distroLooking = codename !== '' && (suite === codename || suite.startsWith(`${codename}-`)) && DISTRO_COMPONENTS.has(component);
  if (!distroLooking || host.includes('launchpad')) return 'third_party';
  // A mirror a person listed in project.yaml (distro_mirrors) counts like the distro's own host; the suite and component rules still apply.
  return DISTRO_HOST.test(host) || mirrors.includes(host) ? 'distro' : 'unknown';
}

/**
 * Where the installed version came from. It is distro when a distro-host repo carries it, or when it is known only to
 * dpkg but a distro repo offers a newer version (an outdated distro package whose old version left the index).
 * It is unknown when the only carriers are repos that look like a distro mirror but are not on a distro host, or there is
 * no apt-cache data at all. It is third-party when a clearly different repo carries it (nginx.org, docker, PPAs).
 * Otherwise it was installed locally. `unknown` and `third_party` both mean "do not trust distro advisories for this".
 */
export function classifyOrigin(origin: PackageOrigin | undefined, codename: string, mirrors: readonly string[] = []): { kind: OriginKind; repo?: string } {
  if (!origin) return { kind: 'unknown' };
  const repos = origin.sources.filter((s) => s !== LOCAL_STATUS);
  if (repos.length > 0) {
    const kinds = repos.map((s) => [s, repoKind(s, codename, mirrors)] as const);
    const distro = kinds.find(([, k]) => k === 'distro');
    if (distro) return { kind: 'distro', repo: distro[0] };
    const unknown = kinds.find(([, k]) => k === 'unknown');
    return unknown ? { kind: 'unknown', repo: unknown[0] } : { kind: 'third_party', repo: repos[0] };
  }
  let unknownOffer: string | undefined;
  for (const offered of origin.available) {
    if (compareDebVersions(offered.version, origin.installed) <= 0) continue;
    const kinds = offered.sources.map((s) => [s, repoKind(s, codename, mirrors)] as const);
    const distro = kinds.find(([, k]) => k === 'distro');
    if (distro) return { kind: 'distro', repo: distro[0] };
    unknownOffer ??= kinds.find(([, k]) => k === 'unknown')?.[0];
  }
  return unknownOffer !== undefined ? { kind: 'unknown', repo: unknownOffer } : { kind: 'local' };
}

/** True when no package lists any repository source for any version: apt lists were cleaned or never fetched, so origins can't be known. */
export function aptListsEmpty(origins: Record<string, PackageOrigin>): boolean {
  return !Object.values(origins).some((o) => [...o.sources, ...o.available.flatMap((v) => v.sources)].some((s) => s !== LOCAL_STATUS));
}

export const ORIGINS_UNAVAILABLE_MESSAGE = 'apt-cache policy failed; origins cannot be determined';

/** Why package origins can't be told on this snapshot, or undefined when they can. */
export function originsProblem(snap: Pick<HostSnapshot, 'origins' | 'origins_unavailable'>): 'failed' | 'empty' | undefined {
  if (snap.origins_unavailable) return 'failed';
  return aptListsEmpty(snap.origins) ? 'empty' : undefined;
}
