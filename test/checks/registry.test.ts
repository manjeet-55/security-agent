import { describe, expect, it } from 'vitest';
import { CHECK_TYPES } from '../../src/checks/registry.js';

describe('CHECK_TYPES', () => {
  it('registers all seven external check types', () => {
    expect([...CHECK_TYPES.keys()].sort()).toEqual([
      'exposed_path',
      'header_budget',
      'http_cookie',
      'http_header',
      'http_redirect',
      'port_exposure',
      'tls',
    ]);
  });
});
