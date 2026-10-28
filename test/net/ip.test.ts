import { describe, expect, it } from 'vitest';
import { NetError } from '../../src/net/errors.js';
import { isPrivateAddress, resolveAddresses, stripBrackets } from '../../src/net/ip.js';

describe('isPrivateAddress', () => {
  it.each([
    ['10.1.2.3', true],
    ['172.16.0.1', true],
    ['172.31.250.10', true],
    ['192.168.1.1', true],
    ['127.0.0.1', true],
    ['169.254.169.254', true],
    ['100.64.0.1', true],
    ['::1', true],
    ['fd00::1', true],
    ['fe80::1', true],
    ['::ffff:10.0.0.1', true],
    ['203.0.113.10', false],
    ['8.8.8.8', false],
    ['2001:db8::1', false],
    ['not-an-ip', false],
  ])('%s → %s', (ip, expected) => {
    expect(isPrivateAddress(ip)).toBe(expected);
  });
});

describe('resolveAddresses', () => {
  it('returns IP literals unchanged', async () => {
    expect(await resolveAddresses('203.0.113.10', 4)).toEqual(['203.0.113.10']);
    expect(await resolveAddresses('[::1]', 6)).toEqual(['::1']);
  });
  it('resolves localhost', async () => {
    expect(await resolveAddresses('localhost', 4)).toContain('127.0.0.1');
  });
  it('wraps DNS failures in NetError', async () => {
    await expect(resolveAddresses('does-not-exist.invalid', 4)).rejects.toBeInstanceOf(NetError);
  });
  it('strips IPv6 brackets', () => {
    expect(stripBrackets('[::1]')).toBe('::1');
  });
});
