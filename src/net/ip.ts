import { lookup } from 'node:dns/promises';
import { BlockList, isIP, type LookupFunction } from 'node:net';
import { toNetError } from './errors.js';

// One list for both families: Node matches IPv4-mapped IPv6 (including hex form) against the IPv4 subnets.
const NON_PUBLIC = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.0.0.0', 24],
  ['192.168.0.0', 16],
  ['198.18.0.0', 15],
  ['224.0.0.0', 4],
  ['240.0.0.0', 4],
] as const) {
  NON_PUBLIC.addSubnet(net, prefix, 'ipv4');
}
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
  ['ff00::', 8],
] as const) {
  NON_PUBLIC.addSubnet(net, prefix, 'ipv6');
}

/** Expands an IPv6 address (with `::` compression and/or a trailing dotted IPv4) to its 8 hextets. */
function expandIpv6(ip: string): number[] {
  let text = ip;
  const dotted = /^(.*:)(\d+)\.(\d+)\.(\d+)\.(\d+)$/.exec(text);
  if (dotted) {
    const [, head, a, b, c, d] = dotted;
    text = `${head}${((Number(a) << 8) | Number(b)).toString(16)}:${((Number(c) << 8) | Number(d)).toString(16)}`;
  }
  const parse = (part: string): number[] => (part === '' ? [] : part.split(':').map((h) => parseInt(h, 16)));
  const [left = '', right] = text.split('::');
  if (right === undefined) return parse(left);
  const l = parse(left);
  const r = parse(right);
  return [...l, ...new Array<number>(8 - l.length - r.length).fill(0), ...r];
}

function hextetsToV4(hi: number, lo: number): string {
  return `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;
}

export function stripBrackets(host: string): string {
  return host.replace(/^\[|\]$/g, '');
}

/**
 * True for addresses that are not public unicast: loopback, RFC 1918, CGNAT, link-local, unique-local,
 * unspecified, reserved and multicast. IPv4-mapped, NAT64 and 6to4 forms are judged by the IPv4 they embed.
 */
export function isPrivateAddress(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return NON_PUBLIC.check(ip, 'ipv4');
  if (version !== 6) return false;
  if (NON_PUBLIC.check(ip, 'ipv6')) return true;
  const h = expandIpv6(ip);
  const [h0 = 0, h1 = 0, h2 = 0] = h;
  if (h0 === 0x64 && h1 === 0xff9b && h.slice(2, 6).every((x) => x === 0)) {
    return isPrivateAddress(hextetsToV4(h[6] ?? 0, h[7] ?? 0));
  }
  if (h0 === 0x2002) return isPrivateAddress(hextetsToV4(h1, h2));
  return false;
}

/** Resolves a hostname for the given family; IP literals are returned as-is. DNS failures become NetError. */
export async function resolveAddresses(hostname: string, family: 4 | 6): Promise<string[]> {
  const bare = stripBrackets(hostname);
  if (isIP(bare)) return [bare];
  try {
    const results = await lookup(bare, { family, all: true });
    return results.map((r) => r.address);
  } catch (e) {
    throw toNetError(e, 'DNS_FAILED');
  }
}

/**
 * A dns.lookup replacement that answers only with addresses the scope guard already validated, so a name
 * that re-resolves differently (DNS rebinding) cannot steer a probe elsewhere.
 */
export function pinnedLookup(addresses: readonly string[]): LookupFunction {
  const pinned = addresses
    .map((a) => stripBrackets(a))
    .map((address) => ({ address, family: isIP(address) }))
    .filter((a) => a.family !== 0);
  return (hostname, options, callback) => {
    const requested = options.family === 'IPv4' ? 4 : options.family === 'IPv6' ? 6 : (options.family ?? 0);
    const list = pinned.filter((a) => requested === 0 || a.family === requested);
    const first = list[0];
    if (!first) {
      const err = Object.assign(new Error(`no validated address for ${hostname}`), { code: 'ENOTFOUND' }) as NodeJS.ErrnoException;
      if (options.all) callback(err, []);
      else callback(err, '', 0);
      return;
    }
    if (options.all) callback(null, list);
    else callback(null, first.address, first.family);
  };
}
