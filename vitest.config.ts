import { defineConfig } from 'vitest/config';

// Lightweight vitest setup: pick up *.test.ts files under test/ts and
// ts/ itself so co-located tests work too. No globals — tests import
// expect/it/describe explicitly so static-tooling can see them.
export default defineConfig({
  test: {
    include: ['test/ts/**/*.test.ts', 'ts/**/*.test.ts'],
    environment: 'node',
    reporters: ['default'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'lcov'],
      include: ['ts/**/*.ts'],
      exclude: ['ts/**/*.test.ts'],
    },
  },
});
