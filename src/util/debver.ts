/** Debian version comparison (deb-version(7)): epoch, then upstream version, then revision; `~` sorts before everything. */
export function compareDebVersions(a: string, b: string): number {
  const pa = split(a);
  const pb = split(b);
  if (pa.epoch !== pb.epoch) return pa.epoch < pb.epoch ? -1 : 1;
  return compareFragment(pa.upstream, pb.upstream) || compareFragment(pa.revision, pb.revision);
}

function split(version: string): { epoch: number; upstream: string; revision: string } {
  const v = version.trim();
  const colon = v.indexOf(':');
  const epoch = colon === -1 ? 0 : Number(v.slice(0, colon)) || 0;
  const rest = colon === -1 ? v : v.slice(colon + 1);
  const dash = rest.lastIndexOf('-');
  return dash === -1 ? { epoch, upstream: rest, revision: '' } : { epoch, upstream: rest.slice(0, dash), revision: rest.slice(dash + 1) };
}

function isDigit(c: string | undefined): boolean {
  return c !== undefined && c >= '0' && c <= '9';
}

/** dpkg's order(): digits and end-of-string 0, `~` -1, letters their code, other characters code + 256. */
function order(c: string | undefined): number {
  if (c === undefined || isDigit(c)) return 0;
  if (c === '~') return -1;
  if (/^[A-Za-z]$/.test(c)) return c.charCodeAt(0);
  return c.charCodeAt(0) + 256;
}

function compareFragment(a: string, b: string): number {
  let i = 0;
  let j = 0;
  while (i < a.length || j < b.length) {
    let firstDiff = 0;
    while ((i < a.length && !isDigit(a[i])) || (j < b.length && !isDigit(b[j]))) {
      const ac = order(a[i]);
      const bc = order(b[j]);
      if (ac !== bc) return ac < bc ? -1 : 1;
      i += 1;
      j += 1;
    }
    while (a[i] === '0') i += 1;
    while (b[j] === '0') j += 1;
    while (isDigit(a[i]) && isDigit(b[j])) {
      if (!firstDiff) firstDiff = a.charCodeAt(i) - b.charCodeAt(j);
      i += 1;
      j += 1;
    }
    if (isDigit(a[i])) return 1;
    if (isDigit(b[j])) return -1;
    if (firstDiff) return firstDiff < 0 ? -1 : 1;
  }
  return 0;
}
