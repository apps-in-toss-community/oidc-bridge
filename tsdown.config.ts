import { defineConfig } from 'tsdown';

export default defineConfig({
  entry: {
    server: 'src/server.ts',
    cli: 'cli/index.ts',
  },
  format: 'esm',
  outDir: 'dist',
});
