import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'sqlite',
  schema: './src/storage/schema.sqlite.ts',
  out: './drizzle/sqlite',
  dbCredentials: {
    url: process.env.SQLITE_PATH ?? './oidc-bridge.sqlite',
  },
  strict: true,
  verbose: true,
});
