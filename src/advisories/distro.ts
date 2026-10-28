import type { OsRelease } from '../host/parse.js';

export interface Distro {
  family: 'ubuntu' | 'debian';
  /** OSV ecosystem, e.g. "Ubuntu:24.04:LTS" or "Debian:12". */
  ecosystem: string;
  codename: string;
  version: string;
}

export function distroOf(os: OsRelease): Distro | undefined {
  if (os.id === 'ubuntu' && /^\d\d\.\d\d$/.test(os.version_id)) {
    const [yy = '', mm = ''] = os.version_id.split('.');
    const lts = mm === '04' && Number(yy) % 2 === 0;
    return { family: 'ubuntu', ecosystem: `Ubuntu:${os.version_id}${lts ? ':LTS' : ''}`, codename: os.codename, version: os.version_id };
  }
  const major = /^\d+/.exec(os.version_id)?.[0];
  if (os.id === 'debian' && major) return { family: 'debian', ecosystem: `Debian:${major}`, codename: os.codename, version: major };
  return undefined;
}
