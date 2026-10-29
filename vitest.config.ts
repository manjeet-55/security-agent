import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    setupFiles: ['test/setup/fake-clock.ts', 'test/setup/config-dir.ts'],
    testTimeout: 20_000,
  },
});
