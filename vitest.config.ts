import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['test/**/*.test.ts'],
    setupFiles: ['test/setup/fake-clock.ts'],
    testTimeout: 20_000,
  },
});
