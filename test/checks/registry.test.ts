import { describe, expect, it } from 'vitest';
import { CHECK_TYPES } from '../../src/checks/registry.js';

describe('CHECK_TYPES', () => {
  it('registers all eleven check types', () => {
    expect([...CHECK_TYPES.keys()].sort()).toEqual([
      'code_secrets',
      'exposed_path',
      'header_budget',
      'host_config',
      'host_package',
      'http_cookie',
      'http_cors',
      'http_header',
      'http_redirect',
      'port_exposure',
      'tls',
    ]);
  });
});
