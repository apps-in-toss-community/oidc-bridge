/**
 * Node.js entry-point shim.
 *
 * The bootstrap logic lives in `src/runtime/node.ts`. This file re-exports
 * everything from there so that:
 *   - `pnpm start` (`node dist/server.mjs`) continues to work unchanged.
 *   - `src/server.test.ts` imports keep resolving from `./server.js`.
 *   - The Workers entry (`src/runtime/workers.ts`) is a sibling that shares
 *     the same `createApp(...)` core without touching this file.
 */

import { createLogger } from './logger.js';
import { main } from './runtime/node.js';

export * from './runtime/node.js';

// Only run main() when this file is the process entry point (i.e., production
// `node dist/server.mjs`). Importing server.ts in tests must not boot the HTTP
// listener.
const invokedAsEntrypoint = (() => {
  const argv1 = process.argv[1];
  if (!argv1) return false;
  return import.meta.url === `file://${argv1}` || import.meta.url.endsWith(argv1);
})();

if (invokedAsEntrypoint) {
  main().catch((err) => {
    createLogger().fatal({ err }, 'oidc-bridge bootstrap failed');
    process.exit(1);
  });
}
