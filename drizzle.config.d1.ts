import { defineConfig } from 'drizzle-kit';

export default defineConfig({
  dialect: 'sqlite',
  schema: './src/storage/schema.d1.ts',
  out: './drizzle/d1',
  // D1 schema uses the same drizzle-orm/sqlite-core builders; only the
  // runtime driver differs. drizzle-kit generates standard SQLite DDL.
  strict: true,
  verbose: true,
});
