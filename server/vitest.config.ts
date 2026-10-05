import { defineConfig } from 'vitest/config';

export default defineConfig({
  // Resolve @tamodak/protocol to its TypeScript sources, so tests never run a stale build of it.
  resolve: { conditions: ['source'] },
  ssr: { resolve: { conditions: ['source'] } },
  test: {
    globalSetup: ['test/support/globalSetup.ts'],
    // Each file gets its own database, but the long-poll and push tests measure time, so files
    // run one after another to keep those timings honest on a busy machine.
    fileParallelism: false,
    testTimeout: 20_000,
    hookTimeout: 60_000,
  },
});
