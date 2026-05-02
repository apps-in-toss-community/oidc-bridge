import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    isolate: true,
    pool: 'forks',
    forks: { singleFork: false },
    testTimeout: 15_000,
    include: ['src/**/*.test.ts', 'cli/**/*.test.ts'],
  },
});
