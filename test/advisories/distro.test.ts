import { describe, expect, it } from 'vitest';
import { distroOf } from '../../src/advisories/distro.js';

const os = (id: string, version_id: string, codename: string) => ({ id, version_id, codename, pretty_name: '' });

describe('distroOf', () => {
  it.each([
    [os('ubuntu', '24.04', 'noble'), 'Ubuntu:24.04:LTS'],
    [os('ubuntu', '22.04', 'jammy'), 'Ubuntu:22.04:LTS'],
    [os('ubuntu', '24.10', 'oracular'), 'Ubuntu:24.10'],
    [os('debian', '12', 'bookworm'), 'Debian:12'],
    [os('debian', '13', 'trixie'), 'Debian:13'],
  ])('%j → %s', (release, ecosystem) => {
    expect(distroOf(release)?.ecosystem).toBe(ecosystem);
  });

  it('is undefined for other distros', () => {
    expect(distroOf(os('rhel', '9.4', ''))).toBeUndefined();
  });
});
