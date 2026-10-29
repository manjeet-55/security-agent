export interface OsRelease {
  id: string;
  version_id: string;
  codename: string;
  pretty_name: string;
}

export interface InstalledPackage {
  name: string;
  arch?: string;
  /** dpkg's three-character status abbreviation: want, state, error flag (e.g. "ii ", "hi ", "iU ", "iHR"). */
  state: string;
  version: string;
  source: string;
  source_version: string;
}

/**
 * apt-cache policy for one package. `sources` lists where the installed version is available
 * ("<url> <suite>/<component> <arch> Packages" or /var/lib/dpkg/status). `available` holds the other
 * versions the configured repos offer: an outdated distro package often shows its installed version
 * only under /var/lib/dpkg/status, because the archive index keeps just the newest version.
 */
export interface PackageOrigin {
  installed: string;
  sources: string[];
  available: Array<{ version: string; sources: string[] }>;
}

export interface ListeningSocket {
  address: string;
  port: number;
  process?: string;
}

export function parseOsRelease(text: string): OsRelease {
  const kv: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const m = /^([A-Z_]+)=(.*)$/.exec(line.trim());
    if (m?.[1]) kv[m[1]] = (m[2] ?? '').replace(/^"(.*)"$/, '$1');
  }
  return {
    id: kv.ID ?? '',
    version_id: kv.VERSION_ID ?? '',
    codename: kv.VERSION_CODENAME ?? kv.UBUNTU_CODENAME ?? '',
    pretty_name: kv.PRETTY_NAME ?? '',
  };
}

/**
 * dpkg-query lines "<status>\t<name[:arch]>\t<version>\t<source>\t<source version>". The status is three characters
 * (want, state, error); a package counts as installed unless its state is "n" (not-installed) or "c" (config-files),
 * so held ("hi"), reinstall-required ("iR") and half-configured rows still count. The status is kept on the package:
 * `isSettled` says whether it is fully installed.
 */
export function parsePackages(text: string): InstalledPackage[] {
  const out: InstalledPackage[] = [];
  for (const line of text.split('\n')) {
    const [status, nameArch, version, source, sourceVersion] = line.split('\t');
    const dpkgState = status?.[1];
    if (!dpkgState || dpkgState === 'n' || dpkgState === 'c' || !nameArch || !version) continue;
    const [name = nameArch, arch] = nameArch.split(':');
    out.push({
      name,
      ...(arch ? { arch } : {}),
      state: (status ?? '').padEnd(3, ' ').slice(0, 3),
      version,
      source: source || name,
      source_version: sourceVersion || version,
    });
  }
  return out;
}

/** Fully installed and configured: state installed, triggers-awaited or triggers-pending (any want, such as hold) and no error flag. */
export function isSettled(pkg: Pick<InstalledPackage, 'state'>): boolean {
  return /^.[iWt] $/.test(pkg.state);
}

const DPKG_STATE_NAMES: Record<string, string> = {
  H: 'half-installed',
  U: 'unpacked but not configured',
  F: 'half-configured',
  W: 'triggers awaited',
  t: 'triggers pending',
};

/** e.g. "unpacked but not configured (iU)", "half-installed, reinstall required (iHR)". */
export function describeDpkgState(state: string): string {
  const parts: string[] = [];
  const stateChar = state[1];
  if (stateChar && stateChar !== 'i') parts.push(DPKG_STATE_NAMES[stateChar] ?? `state ${stateChar}`);
  const flag = state[2];
  if (flag && flag !== ' ') parts.push(flag === 'R' ? 'reinstall required' : `error flag ${flag}`);
  return `${parts.join(', ') || 'installed'} (${state.trimEnd()})`;
}

/** apt-cache policy blocks → per installed package: the installed ("***") version's sources plus the other offered versions. */
export function parseAptPolicy(text: string): Record<string, PackageOrigin> {
  const out: Record<string, PackageOrigin> = {};
  let entry: PackageOrigin | undefined;
  let target: string[] | undefined;
  for (const line of text.split('\n')) {
    const header = /^([^\s:]+)(?::[^\s:]+)?:$/.exec(line);
    if (header?.[1]) {
      entry = { installed: '', sources: [], available: [] };
      out[header[1]] = entry;
      target = undefined;
      continue;
    }
    const version = /^ (\*\*\*| {3}) (\S+) -?\d+$/.exec(line);
    if (version?.[2] && entry) {
      if (version[1] === '***') {
        entry.installed = version[2];
        target = entry.sources;
      } else {
        const offered = { version: version[2], sources: [] as string[] };
        entry.available.push(offered);
        target = offered.sources;
      }
      continue;
    }
    const source = /^ {8}-?\d+ (.+)$/.exec(line);
    if (source?.[1] && target) target.push(source[1].trim());
  }
  for (const [name, origin] of Object.entries(out)) if (!origin.installed) delete out[name];
  return out;
}

export function parseSshdT(text: string): Record<string, string> {
  const out: Record<string, string> = {};
  for (const line of text.split('\n')) {
    const m = /^(\S+)\s+(.*)$/.exec(line.trim());
    if (!m?.[1]) continue;
    const key = m[1].toLowerCase();
    const value = m[2] ?? '';
    out[key] = out[key] === undefined ? value : `${out[key]} ${value}`;
  }
  return out;
}

export function parseListening(text: string): ListeningSocket[] {
  const out: ListeningSocket[] = [];
  for (const line of text.split('\n')) {
    const cols = line.trim().split(/\s+/);
    const local = cols[3];
    if (cols[0] !== 'LISTEN' || !local) continue;
    const idx = local.lastIndexOf(':');
    const port = Number(local.slice(idx + 1));
    if (idx === -1 || !Number.isInteger(port)) continue;
    const address = local
      .slice(0, idx)
      .replace(/^\[|\]$/g, '')
      .replace(/%.*$/, '');
    const process = /users:\(\("([^"]+)"/.exec(line)?.[1];
    out.push({ address, port, ...(process ? { process } : {}) });
  }
  return out;
}

export function parseAutoUpgrades(text: string): { enabled: boolean; installed: boolean } {
  return {
    enabled: /^APT::Periodic::Unattended-Upgrade "1";/m.test(text),
    installed: /^[ih]i\s*unattended-upgrades\s*$/m.test(text),
  };
}

export function parseReboot(text: string): { required: boolean; packages: string[] } {
  const [first, ...rest] = text
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean);
  return { required: first === 'required', packages: first === 'required' ? rest : [] };
}

/** Values of every (uncommented) occurrence of a simple directive in `nginx -T` output. */
export function nginxDirectiveValues(config: string, directive: string): string[] {
  const pattern = new RegExp(`(?:^|[\\s;{}])${directive}\\s+([^;{}]*);`, 'g');
  const values: string[] = [];
  for (const raw of config.split('\n')) {
    const line = raw.replace(/#.*$/, '');
    for (const m of line.matchAll(pattern)) if (m[1] !== undefined) values.push(m[1].trim());
  }
  return values;
}
