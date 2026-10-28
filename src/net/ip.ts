import { lookup } from 'node:dns/promises';
import { BlockList, isIP } from 'node:net';
import { toNetError } from './errors.js';

const PRIVATE_V4 = new BlockList();
for (const [net, prefix] of [
  ['0.0.0.0', 8],
  ['10.0.0.0', 8],
  ['100.64.0.0', 10],
  ['127.0.0.0', 8],
  ['169.254.0.0', 16],
  ['172.16.0.0', 12],
  ['192.168.0.0', 16],
] as const) {
  PRIVATE_V4.addSubnet(net, prefix, 'ipv4');
}

const PRIVATE_V6 = new BlockList();
for (const [net, prefix] of [
  ['::', 128],
  ['::1', 128],
  ['fc00::', 7],
  ['fe80::', 10],
] as const) {
  PRIVATE_V6.addSubnet(net, prefix, 'ipv6');
}

export function stripBrackets(host: string): string {
  return host.replace(/^\[|\]$/g, '');
}

/** True for loopback, RFC 1918, CGNAT, link-local, unique-local and unspecified addresses. */
export function isPrivateAddress(ip: string): boolean {
  const version = isIP(ip);
  if (version === 4) return PRIVATE_V4.check(ip, 'ipv4');
  if (version === 6) {
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(ip)?.[1];
    if (mapped) return PRIVATE_V4.check(mapped, 'ipv4');
    return PRIVATE_V6.check(ip, 'ipv6');
  }
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
