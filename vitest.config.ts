import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    globals: false,
    isolate: true,
    pool: 'forks',
    forks: { singleFork: false },
    testTimeout: 15_000,
    projects: [
      {
        extends: true,
        test: {
          name: 'unit',
          include: ['src/**/*.test.ts', 'cli/**/*.test.ts', 'test/smoke/**/*.test.ts'],
          exclude: ['test/live/**'],
        },
      },
      {
        extends: true,
        test: {
          name: 'live',
          include: ['test/live/**/*.test.ts'],
        },
      },
    ],
  },
});
