import { describe, expect, it } from 'vitest';
import { CHECK_TYPES } from '../../src/checks/registry.js';

describe('CHECK_TYPES', () => {
  it('registers all fourteen check types', () => {
    expect([...CHECK_TYPES.keys()].sort()).toEqual([
      'code_dependencies',
      'code_secrets',
      'dns_dangling',
      'exposed_path',
      'header_budget',
      'host_config',
      'host_package',
      'http_cookie',
      'http_cors',
      'http_header',
      'http_redirect',
      'lb_bypass',
      'port_exposure',
      'tls',
    ]);
  });
});
