import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'postgresql',
  schema: './src/storage/schema.pg.ts',
  out: './drizzle/pg',
  // Connection is only needed for `drizzle-kit migrate`. Generation is offline.
  dbCredentials: {
    url: process.env.PG_DATABASE_URL ?? 'postgresql://localhost:5432/oidc_bridge',
  },
  strict: true,
  verbose: true,
});
