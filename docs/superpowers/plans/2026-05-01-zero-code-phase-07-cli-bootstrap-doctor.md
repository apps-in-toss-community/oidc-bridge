# oidc-bridge zero-code mode — Phase 7: CLI bootstrap + doctor

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** End-to-end `pnpm bridge bootstrap` and `pnpm bridge doctor` commands. `bootstrap` writes a fresh SQLite DB + master-key file + first user + first API token + first workspace, and prints a printable summary the operator copies into their `.env`. `doctor` runs env / DB / master-key / sandbox-Toss probes and prints a green/yellow/red report.

**Architecture:** Both commands are thin orchestrators over modules already shipped in Phases 1, 2, 6. `bootstrap` runs in a single transaction over a temp SQLite file (no running bridge required) and never touches Postgres. `doctor` runs in **probe mode** — opens connections / fetches keys / synthesises a Toss `/login-me` call only against a `sandbox.cert.pem` if provided, and degrades gracefully (yellow, not red) when optional pieces are absent. Both commands write structured JSON when stdout is not a TTY (so CI / superuser orchestration scripts can parse them) and human-friendly tables otherwise. No new prod deps; doctor's TTY detection uses Node's `process.stdout.isTTY`.

**Tech stack:** TypeScript ESM strict, `commander` (already from Phase 2's CLI scaffold), `bcryptjs` (already), `node:crypto` (random for API tokens), `vitest`. Adds `chalk@5` (dev-time terminal colors) **only** if not already present from Phase 0; if absent, fall back to ANSI escape strings (a 5-line helper) — do not introduce a new dep just for color.

---

## Universal invariants (apply to every task)

1. **TDD.** Failing test → minimal code → green → commit.
2. **Frequent commits.** Each red→green cycle is a commit.
3. **No premature abstractions.** No "plugin" doctor probes, no extension hooks. Probes are a fixed list defined in this phase.
4. **No PII / secrets in logs.** `bootstrap` prints the API token plaintext exactly **once**, to stdout, with a banner instructing the operator to save it now. After that the plaintext is unrecoverable.
5. **Bridge never spontaneously calls Toss.** `doctor` only calls Toss if the operator passes `--cert` / `--key` flags pointing at a sandbox cert. Default `doctor` skips the Toss probe entirely (prints yellow).
6. **Toss `refresh_token` never leaves the sealed wrapper.** The doctor Toss probe calls `/login-me` — a read-only operation — against a fresh authorization code; it does **not** call `refresh-token` or `access-remove`.
7. **Public clients use `Origin`, never `client_secret`.** Unaffected.
8. **mTLS material never returns from any GET.** Unaffected.
9. **Cloud-agnostic.** No GCP-specific code. Both commands work on a laptop with no cloud access.
10. **Self-host first-class.** This phase is **the** self-host UX. A self-host operator's onboarding is `pnpm bridge bootstrap` then `pnpm bridge doctor`; no other steps.
11. **Bite-sized tasks.** Each step ≈2–5 minutes.
12. **Lint + typecheck + test pass on every commit.**

## Files this phase touches

```
cli/
  commands/
    bootstrap.ts                 # NEW — writes DB + first user + first workspace + master-key file
    bootstrap.test.ts            # NEW — golden output + side-effect assertions
    doctor.ts                    # NEW — probe runner + report formatter
    doctor.test.ts               # NEW — green/yellow/red matrix
    doctor-probes/
      env-probe.ts               # NEW — checks required envs are present + well-shaped
      db-probe.ts                # NEW — connect + run pending migrations + simple SELECT
      master-key-probe.ts        # NEW — fetch + decode + size check
      jwks-probe.ts              # NEW — load active signing key + verify a self-signed JWT roundtrip
      toss-probe.ts              # NEW — optional, runs RealTossAdapter.loginMe against sandbox
  output.ts                      # NEW — TTY-aware reporter (table vs JSON)
  output.test.ts                 # NEW — TTY toggle assertion
  index.ts                       # MODIFY — register bootstrap + doctor commands
docs/
  RUNBOOK.md                     # MODIFY — replaces "first-time setup" section
  SELF_HOSTING.md                # CREATE-OR-MODIFY — bootstrap walkthrough
```

## Pre-flight (do this once before Task 1)

```bash
git fetch origin
git checkout main && git pull
git checkout -b feat/zero-code-phase-07 origin/main
pnpm install
pnpm typecheck && pnpm lint && pnpm test
```

If any check fails, stop. Phases 0–6 are not green; fix that before continuing.

This phase depends on:

- Phase 1's `MasterKeyProvider` (env / file), `Storage` (sqlite), and `deriveSealingKey`.
- Phase 2's `service.workspaces.create`, `service.apps.create`, `service.apiTokens.create`.
- Phase 5's `RealTossAdapter` (used only by the optional Toss probe).
- Phase 6's `runUserSetPassword` (re-used by `bootstrap` to set the optional admin password).
- The CLI scaffold from Phase 2 (`commander` program, `cli/index.ts`).

---

## Task 1: `cli/output.ts` — TTY-aware reporter

**Files:**
- Create: `cli/output.ts`
- Test: `cli/output.test.ts`

A two-method reporter: `report(items)` for tabular human output, `json(items)` for machine output. The CLI commands ask the reporter to render once at the end; choice of mode is automatic based on `process.stdout.isTTY`, with explicit override via `--json`.

- [ ] **Step 1: Failing test**

```ts
// cli/output.test.ts
import { describe, it, expect, vi } from 'vitest';
import { createReporter } from './output.js';

describe('createReporter', () => {
  it('emits JSON when not a TTY', () => {
    const writes: string[] = [];
    const stdout = { isTTY: false, write: (s: string) => { writes.push(s); return true; } } as unknown as NodeJS.WriteStream;
    const r = createReporter({ stdout });
    r.report({ status: 'green', items: [{ name: 'env', state: 'green', detail: 'ok' }] });
    const all = writes.join('');
    expect(all.trim()).toBe(JSON.stringify({ status: 'green', items: [{ name: 'env', state: 'green', detail: 'ok' }] }));
  });

  it('emits a human table when a TTY', () => {
    const writes: string[] = [];
    const stdout = { isTTY: true, write: (s: string) => { writes.push(s); return true; } } as unknown as NodeJS.WriteStream;
    const r = createReporter({ stdout });
    r.report({ status: 'green', items: [{ name: 'env', state: 'green', detail: 'ok' }] });
    const all = writes.join('');
    expect(all).toContain('env');
    expect(all).toContain('green');
    expect(all).toContain('ok');
    // Should NOT be valid JSON.
    expect(() => JSON.parse(all)).toThrow();
  });

  it('--json override forces JSON even on TTY', () => {
    const writes: string[] = [];
    const stdout = { isTTY: true, write: (s: string) => { writes.push(s); return true; } } as unknown as NodeJS.WriteStream;
    const r = createReporter({ stdout, forceJson: true });
    r.report({ status: 'green', items: [] });
    expect(() => JSON.parse(writes.join('').trim())).not.toThrow();
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// cli/output.ts
export type ProbeState = 'green' | 'yellow' | 'red';

export interface ProbeItem {
  name: string;
  state: ProbeState;
  detail: string;
}

export interface ProbeReport {
  status: ProbeState;
  items: ProbeItem[];
}

export interface ReporterOpts {
  stdout: NodeJS.WriteStream;
  forceJson?: boolean;
}

export interface Reporter {
  report(rep: ProbeReport): void;
}

export function createReporter(opts: ReporterOpts): Reporter {
  const useJson = opts.forceJson === true || !opts.stdout.isTTY;
  return {
    report(rep) {
      if (useJson) {
        opts.stdout.write(JSON.stringify(rep) + '\n');
        return;
      }
      const w = (s: string) => opts.stdout.write(s);
      const colorFor: Record<ProbeState, string> = { green: '\x1b[32m', yellow: '\x1b[33m', red: '\x1b[31m' };
      const reset = '\x1b[0m';
      const nameWidth = Math.max(4, ...rep.items.map((i) => i.name.length));
      w(`Overall: ${colorFor[rep.status]}${rep.status}${reset}\n`);
      for (const item of rep.items) {
        w(`  ${item.name.padEnd(nameWidth)}  ${colorFor[item.state]}${item.state.padEnd(6)}${reset}  ${item.detail}\n`);
      }
    },
  };
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add cli/output.ts cli/output.test.ts
git commit -m "feat(cli): TTY-aware reporter (table vs JSON)"
```

---

## Task 2: `bootstrap` command — happy path

**Files:**
- Create: `cli/commands/bootstrap.ts`
- Test: `cli/commands/bootstrap.test.ts`

`bootstrap` performs eight side effects in order:

1. Validates target SQLite path does not already contain bridge data (`users` table missing or empty).
2. Generates a 32-byte random master key, writes to `${MASTER_KEY_DIR}/v1.key` with mode `600`.
3. Opens the SQLite DB and runs all migrations.
4. Inserts a `users` row with the given email.
5. Optionally sets the user's password (Phase 6's helper) if `--password` flag is passed.
6. Generates an API token plaintext (`prefix.random`), inserts the SHA-256 hash row.
7. Inserts a default `workspaces` row owned by the user.
8. Prints a copy-pasteable summary including the API token plaintext (only chance to see it).

The function returns the summary as a structured object so tests can assert against it without scraping stdout.

- [ ] **Step 1: Failing test**

```ts
// cli/commands/bootstrap.test.ts
import { describe, it, expect, beforeEach } from 'vitest';
import { mkdtempSync, readFileSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runBootstrap } from './bootstrap.js';
import { openSqliteStorage } from '../../src/storage/sqlite/storage.js';

describe('runBootstrap', () => {
  let tmp: string;
  beforeEach(() => { tmp = mkdtempSync(join(tmpdir(), 'bridge-bootstrap-')); });

  it('happy path creates DB + master key + user + token + workspace', async () => {
    const dbUrl = `sqlite://${join(tmp, 'bridge.db')}`;
    const masterKeyDir = join(tmp, 'keys');
    const summary = await runBootstrap({
      dbUrl,
      masterKeyDir,
      email: 'a@b',
      workspaceName: 'default',
    });

    expect(summary.userId).toMatch(/^u_/);
    expect(summary.workspaceId).toMatch(/^ws_/);
    expect(summary.apiTokenPrefix).toMatch(/^bait_/);
    expect(summary.apiTokenPlaintext.startsWith(summary.apiTokenPrefix + '.')).toBe(true);
    expect(summary.masterKeyVersion).toBe(1);

    // Master key file present, mode 600.
    const masterKeyPath = join(masterKeyDir, 'v1.key');
    const stat = statSync(masterKeyPath);
    // On macOS/Linux, masking with 0o777 isolates the perm bits.
    expect(stat.mode & 0o777).toBe(0o600);
    expect(readFileSync(masterKeyPath).length).toBe(32);

    // DB has the rows we expect.
    const storage = await openSqliteStorage(dbUrl);
    const users = await storage.query<{ id: string; email: string }>(`SELECT id, email FROM users`);
    expect(users).toEqual([{ id: summary.userId, email: 'a@b' }]);
    const ws = await storage.query<{ id: string; name: string }>(`SELECT id, name FROM workspaces`);
    expect(ws).toEqual([{ id: summary.workspaceId, name: 'default' }]);
    const tokens = await storage.query<{ user_id: string; token_hash: string }>(`SELECT user_id, token_hash FROM api_tokens`);
    expect(tokens).toHaveLength(1);
    expect(tokens[0]!.user_id).toBe(summary.userId);
    expect(tokens[0]!.token_hash).not.toBe(summary.apiTokenPlaintext); // hashed
    expect(tokens[0]!.token_hash.length).toBe(64); // sha256 hex
  });

  it('refuses to run if users table already has rows', async () => {
    const dbUrl = `sqlite://${join(tmp, 'bridge.db')}`;
    const masterKeyDir = join(tmp, 'keys');
    await runBootstrap({ dbUrl, masterKeyDir, email: 'a@b', workspaceName: 'first' });
    await expect(
      runBootstrap({ dbUrl, masterKeyDir, email: 'second@b', workspaceName: 'second' }),
    ).rejects.toThrow(/already bootstrapped/);
  });

  it('--password sets password_hash on the new user', async () => {
    const dbUrl = `sqlite://${join(tmp, 'bridge.db')}`;
    const masterKeyDir = join(tmp, 'keys');
    const summary = await runBootstrap({
      dbUrl, masterKeyDir,
      email: 'a@b',
      workspaceName: 'w',
      password: 'pw',
    });
    const storage = await openSqliteStorage(dbUrl);
    const rows = await storage.query<{ password_hash: string | null }>(
      `SELECT password_hash FROM users WHERE id = $1`, [summary.userId],
    );
    expect(rows[0]?.password_hash).not.toBeNull();
  });

  it('refuses non-sqlite dbUrl', async () => {
    await expect(
      runBootstrap({ dbUrl: 'postgres://x', masterKeyDir: tmp, email: 'a@b', workspaceName: 'w' }),
    ).rejects.toThrow(/sqlite/);
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// cli/commands/bootstrap.ts
import { mkdirSync, writeFileSync, existsSync, chmodSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes, createHash } from 'node:crypto';
import { openSqliteStorage } from '../../src/storage/sqlite/storage.js';
import { runUserSetPassword } from './user-set-password.js';

export interface BootstrapOpts {
  dbUrl: string;            // sqlite://...
  masterKeyDir: string;     // dir for v1.key
  email: string;
  workspaceName: string;
  password?: string;        // optional: also set users.password_hash
}

export interface BootstrapSummary {
  userId: string;
  workspaceId: string;
  apiTokenPrefix: string;       // shown publicly (audit log)
  apiTokenPlaintext: string;    // FULL TOKEN — stdout once, never again
  masterKeyVersion: number;
  masterKeyPath: string;
}

export async function runBootstrap(opts: BootstrapOpts): Promise<BootstrapSummary> {
  if (!opts.dbUrl.startsWith('sqlite://')) {
    throw new Error('bootstrap is sqlite-only; dbUrl must start with sqlite://');
  }

  // 1. Open DB, run migrations, refuse if not blank.
  const storage = await openSqliteStorage(opts.dbUrl);
  await storage.migrate();
  const existing = await storage.query<{ count: number }>(`SELECT count(*) as count FROM users`);
  if ((existing[0]?.count ?? 0) > 0) {
    throw new Error('bootstrap: this DB is already bootstrapped (users table not empty)');
  }

  // 2. Master key file.
  mkdirSync(opts.masterKeyDir, { recursive: true });
  const masterKeyPath = join(opts.masterKeyDir, 'v1.key');
  if (existsSync(masterKeyPath)) {
    throw new Error(`bootstrap: master key already exists at ${masterKeyPath}; refusing to overwrite`);
  }
  writeFileSync(masterKeyPath, randomBytes(32));
  chmodSync(masterKeyPath, 0o600);

  // 3. master_keys metadata row (no bytes!).
  await storage.exec(
    `INSERT INTO master_keys (id, version, created_at, provider_ref) VALUES ($1, $2, $3, $4)`,
    [`mk_${randomBytes(8).toString('hex')}`, 1, new Date().toISOString(), `file:${masterKeyPath}`],
  );

  // 4. user.
  const userId = `u_${randomBytes(8).toString('hex')}`;
  await storage.exec(
    `INSERT INTO users (id, email) VALUES ($1, $2)`,
    [userId, opts.email],
  );

  // 5. password (optional).
  if (opts.password) {
    await runUserSetPassword({ dbUrl: opts.dbUrl, email: opts.email, plaintextPassword: opts.password });
  }

  // 6. api_token.
  const apiTokenPrefix = `bait_${randomBytes(4).toString('hex')}`;
  const apiTokenSecret = randomBytes(24).toString('base64url');
  const apiTokenPlaintext = `${apiTokenPrefix}.${apiTokenSecret}`;
  const apiTokenHash = createHash('sha256').update(apiTokenPlaintext).digest('hex');
  await storage.exec(
    `INSERT INTO api_tokens (id, user_id, name, token_hash, scopes, created_at) VALUES ($1, $2, $3, $4, $5, $6)`,
    [
      `tok_${randomBytes(8).toString('hex')}`,
      userId,
      'bootstrap',
      apiTokenHash,
      JSON.stringify(['admin']),
      new Date().toISOString(),
    ],
  );

  // 7. workspace.
  const workspaceId = `ws_${randomBytes(8).toString('hex')}`;
  await storage.exec(
    `INSERT INTO workspaces (id, owner_user_id, name, created_at) VALUES ($1, $2, $3, $4)`,
    [workspaceId, userId, opts.workspaceName, new Date().toISOString()],
  );

  return {
    userId,
    workspaceId,
    apiTokenPrefix,
    apiTokenPlaintext,
    masterKeyVersion: 1,
    masterKeyPath,
  };
}

export function formatBootstrapSummary(s: BootstrapSummary, env: { issuerHint: string }): string {
  return [
    '',
    'Bootstrap complete.',
    '',
    'Save these values now — the API token plaintext will not be shown again.',
    '',
    `  USER_ID=${s.userId}`,
    `  WORKSPACE_ID=${s.workspaceId}`,
    `  ADMIN_API_TOKEN=${s.apiTokenPlaintext}`,
    `  MASTER_KEY_PATH=${s.masterKeyPath}  (mode 600)`,
    '',
    'Add to your bridge .env:',
    '',
    `  BRIDGE_DB_URL=...                       # the sqlite or postgres url you bootstrapped`,
    `  MASTER_KEY_PROVIDER=file`,
    `  MASTER_KEY_DIR=${s.masterKeyPath.replace(/\/v1\.key$/, '')}`,
    `  OIDC_ISSUER=${env.issuerHint}`,
    '',
    'Next: run `pnpm bridge doctor` to verify the install.',
    '',
  ].join('\n');
}
```

- [ ] **Step 4: Run, expect green**

```bash
pnpm vitest run cli/commands/bootstrap.test.ts
```

- [ ] **Step 5: Register the command in `cli/index.ts`**

```ts
program
  .command('bootstrap')
  .description('Initialize a fresh self-host install (sqlite only)')
  .requiredOption('--db <dbUrl>')
  .requiredOption('--master-key-dir <dir>')
  .requiredOption('--email <email>')
  .option('--workspace <name>', 'first workspace name', 'default')
  .option('--password <password>', 'set users.password_hash for session-login preview')
  .option('--issuer-hint <url>', 'shown in printed env summary', 'https://oidc-bridge.example')
  .action(async (cmd) => {
    const summary = await runBootstrap({
      dbUrl: cmd.db,
      masterKeyDir: cmd.masterKeyDir,
      email: cmd.email,
      workspaceName: cmd.workspace,
      password: cmd.password,
    });
    process.stdout.write(formatBootstrapSummary(summary, { issuerHint: cmd.issuerHint }));
  });
```

- [ ] **Step 6: Commit**

```bash
git add cli/commands/bootstrap.ts cli/commands/bootstrap.test.ts cli/index.ts
git commit -m "feat(cli): bootstrap command (sqlite + master key + user + token + workspace)"
```

---

## Task 3: `doctor` env probe

**Files:**
- Create: `cli/commands/doctor-probes/env-probe.ts`
- Test: `cli/commands/doctor-probes/env-probe.test.ts`

The env probe checks: `BRIDGE_DB_URL`, `OIDC_ISSUER`, `OIDC_ACTIVE_KID`, `MASTER_KEY_PROVIDER`. Each missing var → red. Each malformed (e.g. issuer with trailing slash) → yellow.

- [ ] **Step 1: Failing test**

```ts
// cli/commands/doctor-probes/env-probe.test.ts
import { describe, it, expect } from 'vitest';
import { runEnvProbe } from './env-probe.js';

describe('runEnvProbe', () => {
  it('green when all required envs present and well-formed', () => {
    const r = runEnvProbe({
      BRIDGE_DB_URL: 'sqlite:///tmp/bridge.db',
      OIDC_ISSUER: 'https://oidc-bridge.aitc.dev',
      OIDC_ACTIVE_KID: 'k1',
      MASTER_KEY_PROVIDER: 'file',
    });
    expect(r.state).toBe('green');
  });

  it('red when any required env missing', () => {
    const r = runEnvProbe({
      OIDC_ISSUER: 'https://x',
      OIDC_ACTIVE_KID: 'k1',
      MASTER_KEY_PROVIDER: 'file',
    });
    expect(r.state).toBe('red');
    expect(r.detail).toContain('BRIDGE_DB_URL');
  });

  it('yellow when issuer has trailing slash', () => {
    const r = runEnvProbe({
      BRIDGE_DB_URL: 'sqlite:///tmp/bridge.db',
      OIDC_ISSUER: 'https://x/',
      OIDC_ACTIVE_KID: 'k1',
      MASTER_KEY_PROVIDER: 'file',
    });
    expect(r.state).toBe('yellow');
    expect(r.detail).toContain('trailing slash');
  });

  it('red when MASTER_KEY_PROVIDER is unknown', () => {
    const r = runEnvProbe({
      BRIDGE_DB_URL: 'sqlite:///tmp/bridge.db',
      OIDC_ISSUER: 'https://x',
      OIDC_ACTIVE_KID: 'k1',
      MASTER_KEY_PROVIDER: 'wat',
    });
    expect(r.state).toBe('red');
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// cli/commands/doctor-probes/env-probe.ts
import type { ProbeItem } from '../../output.js';

const REQUIRED = ['BRIDGE_DB_URL', 'OIDC_ISSUER', 'OIDC_ACTIVE_KID', 'MASTER_KEY_PROVIDER'];
const VALID_PROVIDERS = new Set(['env', 'file', 'gcpsm']);

export function runEnvProbe(env: Record<string, string | undefined>): ProbeItem {
  const missing = REQUIRED.filter((k) => !env[k]);
  if (missing.length > 0) {
    return { name: 'env', state: 'red', detail: `missing: ${missing.join(', ')}` };
  }
  const issues: string[] = [];
  if (env.OIDC_ISSUER!.endsWith('/')) issues.push('OIDC_ISSUER has trailing slash');
  if (!VALID_PROVIDERS.has(env.MASTER_KEY_PROVIDER!)) {
    return { name: 'env', state: 'red', detail: `MASTER_KEY_PROVIDER must be one of ${[...VALID_PROVIDERS].join('|')}` };
  }
  if (issues.length > 0) {
    return { name: 'env', state: 'yellow', detail: issues.join('; ') };
  }
  return { name: 'env', state: 'green', detail: 'all required envs present and well-formed' };
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add cli/commands/doctor-probes/env-probe.ts cli/commands/doctor-probes/env-probe.test.ts
git commit -m "feat(cli): doctor env probe"
```

---

## Task 4: `doctor` DB probe

**Files:**
- Create: `cli/commands/doctor-probes/db-probe.ts`
- Test: `cli/commands/doctor-probes/db-probe.test.ts`

Connects to the configured DB, runs migrations (idempotent), and runs a `SELECT count(*) FROM users`. Red on any throw; yellow if migrations had to apply (a fresh / behind DB shouldn't fail doctor); green otherwise.

- [ ] **Step 1: Failing test**

```ts
// cli/commands/doctor-probes/db-probe.test.ts
import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runDbProbe } from './db-probe.js';

describe('runDbProbe', () => {
  it('green on a fully-migrated DB', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-db-probe-'));
    const dbUrl = `sqlite://${join(dir, 'bridge.db')}`;
    // First call applies migrations.
    await runDbProbe({ dbUrl });
    // Second call should be green (no migrations applied this time).
    const r = await runDbProbe({ dbUrl });
    expect(r.state).toBe('green');
  });

  it('yellow when migrations had to apply this run', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-db-probe-'));
    const dbUrl = `sqlite://${join(dir, 'bridge.db')}`;
    const r = await runDbProbe({ dbUrl });
    expect(r.state).toBe('yellow');
    expect(r.detail).toContain('migrations applied');
  });

  it('red when dbUrl is invalid', async () => {
    const r = await runDbProbe({ dbUrl: 'wat://nothing' });
    expect(r.state).toBe('red');
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// cli/commands/doctor-probes/db-probe.ts
import type { ProbeItem } from '../../output.js';
import { openStorageFromUrl } from '../../../src/storage/open.js'; // helper from Phase 1 that picks pg vs sqlite

export async function runDbProbe(opts: { dbUrl: string }): Promise<ProbeItem> {
  try {
    const storage = await openStorageFromUrl(opts.dbUrl);
    const before = await storage.currentMigrationVersion();
    await storage.migrate();
    const after = await storage.currentMigrationVersion();
    await storage.query<{ count: number }>(`SELECT count(*) AS count FROM users`);
    if (after > before) {
      return { name: 'db', state: 'yellow', detail: `migrations applied (${before} → ${after})` };
    }
    return { name: 'db', state: 'green', detail: `connected, version=${after}` };
  } catch (err) {
    return { name: 'db', state: 'red', detail: (err as Error).message };
  }
}
```

If `currentMigrationVersion()` is named differently in Phase 1's `Storage` (e.g. `getMigrationVersion`), use the existing name; do not introduce a new method.

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add cli/commands/doctor-probes/db-probe.ts cli/commands/doctor-probes/db-probe.test.ts
git commit -m "feat(cli): doctor db probe"
```

---

## Task 5: `doctor` master-key probe

**Files:**
- Create: `cli/commands/doctor-probes/master-key-probe.ts`
- Test: `cli/commands/doctor-probes/master-key-probe.test.ts`

Resolves the configured `MasterKeyProvider`, fetches version `1`, asserts it is exactly 32 bytes. Red on any throw or wrong size.

- [ ] **Step 1: Failing test**

```ts
// cli/commands/doctor-probes/master-key-probe.test.ts
import { describe, it, expect } from 'vitest';
import { mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runMasterKeyProbe } from './master-key-probe.js';

describe('runMasterKeyProbe', () => {
  it('green for a valid file provider with 32-byte v1 key', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-mk-'));
    writeFileSync(join(dir, 'v1.key'), Buffer.alloc(32, 0x42));
    const r = await runMasterKeyProbe({ provider: 'file', masterKeyDir: dir, version: 1 });
    expect(r.state).toBe('green');
  });

  it('red when key file is wrong size', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-mk-'));
    writeFileSync(join(dir, 'v1.key'), Buffer.alloc(16, 0));
    const r = await runMasterKeyProbe({ provider: 'file', masterKeyDir: dir, version: 1 });
    expect(r.state).toBe('red');
    expect(r.detail).toContain('16 bytes');
  });

  it('red when key file is missing', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-mk-'));
    const r = await runMasterKeyProbe({ provider: 'file', masterKeyDir: dir, version: 1 });
    expect(r.state).toBe('red');
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// cli/commands/doctor-probes/master-key-probe.ts
import type { ProbeItem } from '../../output.js';
import { createMasterKeyProvider } from '../../../src/master-keys/factory.js'; // from Phase 1

export interface MasterKeyProbeOpts {
  provider: 'env' | 'file' | 'gcpsm';
  masterKeyDir?: string;
  version: number;
}

export async function runMasterKeyProbe(opts: MasterKeyProbeOpts): Promise<ProbeItem> {
  try {
    const provider = await createMasterKeyProvider({
      kind: opts.provider,
      fileDir: opts.masterKeyDir,
    });
    const bytes = await provider.getKey(opts.version);
    if (bytes.length !== 32) {
      return { name: 'master-key', state: 'red', detail: `expected 32 bytes, got ${bytes.length} bytes` };
    }
    return { name: 'master-key', state: 'green', detail: `provider=${opts.provider} version=${opts.version}` };
  } catch (err) {
    return { name: 'master-key', state: 'red', detail: (err as Error).message };
  }
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add cli/commands/doctor-probes/master-key-probe.ts cli/commands/doctor-probes/master-key-probe.test.ts
git commit -m "feat(cli): doctor master-key probe"
```

---

## Task 6: `doctor` JWKS probe

**Files:**
- Create: `cli/commands/doctor-probes/jwks-probe.ts`
- Test: `cli/commands/doctor-probes/jwks-probe.test.ts`

Loads the active signing key (from env per Phase 3) and verifies a sign+verify roundtrip. Catches PEM corruption, wrong-format key, etc.

- [ ] **Step 1: Failing test**

```ts
// cli/commands/doctor-probes/jwks-probe.test.ts
import { describe, it, expect } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { runJwksProbe } from './jwks-probe.js';

function rsaPem() {
  const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
  return privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;
}

describe('runJwksProbe', () => {
  it('green for a valid RSA-2048 PEM that signs+verifies', async () => {
    const pem = rsaPem();
    const r = await runJwksProbe({ activeKid: 'k1', signingKeys: { k1: pem } });
    expect(r.state).toBe('green');
  });

  it('red when active kid has no PEM', async () => {
    const r = await runJwksProbe({ activeKid: 'missing', signingKeys: { k1: rsaPem() } });
    expect(r.state).toBe('red');
    expect(r.detail).toContain('missing');
  });

  it('red when PEM is malformed', async () => {
    const r = await runJwksProbe({ activeKid: 'k1', signingKeys: { k1: 'not a pem' } });
    expect(r.state).toBe('red');
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// cli/commands/doctor-probes/jwks-probe.ts
import type { ProbeItem } from '../../output.js';
import { SignJWT, jwtVerify } from 'jose';
import { createPrivateKey, createPublicKey } from 'node:crypto';

export interface JwksProbeOpts {
  activeKid: string;
  signingKeys: Record<string, string>; // kid → pem
}

export async function runJwksProbe(opts: JwksProbeOpts): Promise<ProbeItem> {
  const pem = opts.signingKeys[opts.activeKid];
  if (!pem) {
    return { name: 'jwks', state: 'red', detail: `active kid "${opts.activeKid}" missing from signingKeys` };
  }
  let priv: ReturnType<typeof createPrivateKey>;
  let pub: ReturnType<typeof createPublicKey>;
  try {
    priv = createPrivateKey(pem);
    pub = createPublicKey(pem);
  } catch (err) {
    return { name: 'jwks', state: 'red', detail: `PEM parse failed: ${(err as Error).message}` };
  }
  try {
    const jwt = await new SignJWT({})
      .setProtectedHeader({ alg: 'RS256', kid: opts.activeKid })
      .setIssuedAt()
      .setExpirationTime('1m')
      .sign(priv);
    await jwtVerify(jwt, pub);
    return { name: 'jwks', state: 'green', detail: `kid=${opts.activeKid} sign+verify ok` };
  } catch (err) {
    return { name: 'jwks', state: 'red', detail: `sign/verify roundtrip failed: ${(err as Error).message}` };
  }
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add cli/commands/doctor-probes/jwks-probe.ts cli/commands/doctor-probes/jwks-probe.test.ts
git commit -m "feat(cli): doctor jwks probe (sign+verify roundtrip)"
```

---

## Task 7: `doctor` Toss probe (optional, sandbox cert)

**Files:**
- Create: `cli/commands/doctor-probes/toss-probe.ts`
- Test: `cli/commands/doctor-probes/toss-probe.test.ts`

Optional. Skipped (yellow with detail "no sandbox cert provided") when `--cert` / `--key` flags are absent. Run by `RealTossAdapter.loginMe` against a fixture-friendly sandbox AT — if the operator has only a cert/key but no AT, the probe attempts `loginMe` with a placeholder AT and expects a `FAIL` envelope (which proves mTLS handshake worked, even if the AT is rejected).

This dual-meaning logic is subtle, so the test pins it explicitly.

- [ ] **Step 1: Failing test**

```ts
// cli/commands/doctor-probes/toss-probe.test.ts
import { describe, it, expect, vi } from 'vitest';
import { runTossProbe } from './toss-probe.js';

describe('runTossProbe', () => {
  it('yellow when no cert/key provided (skip)', async () => {
    const r = await runTossProbe({ apiBase: 'https://x', certPem: undefined, keyPem: undefined });
    expect(r.state).toBe('yellow');
    expect(r.detail).toContain('no sandbox cert');
  });

  it('green when adapter.loginMe returns SUCCESS', async () => {
    const fetchImpl = vi.fn(async () => new Response(
      JSON.stringify({ resultType: 'SUCCESS', success: { userKey: 1, scope: 'openid', agreedTerms: [] } }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    ));
    const r = await runTossProbe({
      apiBase: 'https://x.example',
      certPem: 'C',
      keyPem: 'K',
      accessToken: 'doctor_at',
      fetchImpl,
      buildDispatcher: () => ({}),
    });
    expect(r.state).toBe('green');
  });

  it('green when adapter.loginMe returns FAIL with INVALID_TOKEN (handshake worked)', async () => {
    const fetchImpl = vi.fn(async () => new Response(
      JSON.stringify({ resultType: 'FAIL', error: { code: 'INVALID_TOKEN', message: 'fake AT' } }),
      { status: 200, headers: { 'content-type': 'application/json' } },
    ));
    const r = await runTossProbe({
      apiBase: 'https://x.example',
      certPem: 'C',
      keyPem: 'K',
      accessToken: 'fake_at',
      fetchImpl,
      buildDispatcher: () => ({}),
    });
    expect(r.state).toBe('green');
    expect(r.detail).toContain('handshake');
  });

  it('red when adapter.loginMe throws upstream_error (network or TLS fail)', async () => {
    const fetchImpl = vi.fn(async () => { throw new Error('connect ECONNREFUSED'); });
    const r = await runTossProbe({
      apiBase: 'https://x.example',
      certPem: 'C',
      keyPem: 'K',
      accessToken: 'fake_at',
      fetchImpl,
      buildDispatcher: () => ({}),
    });
    expect(r.state).toBe('red');
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// cli/commands/doctor-probes/toss-probe.ts
import type { ProbeItem } from '../../output.js';
import { RealTossAdapter } from '../../../src/toss/real-adapter.js';
import { TossUpstreamError } from '../../../src/toss/adapter.js';

export interface TossProbeOpts {
  apiBase: string;
  certPem: string | undefined;
  keyPem: string | undefined;
  accessToken?: string;
  fetchImpl?: typeof fetch;
  buildDispatcher?: (opts: { certPem: string; keyPem: string }) => unknown;
}

export async function runTossProbe(opts: TossProbeOpts): Promise<ProbeItem> {
  if (!opts.certPem || !opts.keyPem) {
    return { name: 'toss', state: 'yellow', detail: 'no sandbox cert/key provided; skipping (use --cert/--key to enable)' };
  }
  const adapter = new RealTossAdapter({
    apiBase: opts.apiBase,
    getMtlsMaterial: async () => ({ certPem: opts.certPem!, keyPem: opts.keyPem! }),
    fetchImpl: opts.fetchImpl,
    buildDispatcher: opts.buildDispatcher,
  });
  try {
    await adapter.loginMe({ appId: 'doctor' }, { accessToken: opts.accessToken ?? 'doctor_probe_at' });
    return { name: 'toss', state: 'green', detail: 'login-me SUCCESS (mTLS + AT both valid)' };
  } catch (err) {
    if (err instanceof TossUpstreamError && err.code === 'upstream_error') {
      // FAIL envelope path: handshake worked, AT was bad — that's a probe success.
      // (Network/TLS errors also surface as upstream_error; we rely on the message
      //  containing 'Toss FAIL' to disambiguate.)
      const m = err.message;
      if (m.includes('Toss FAIL') || m.includes('INVALID_TOKEN') || m.includes('UNKNOWN')) {
        return { name: 'toss', state: 'green', detail: `mTLS handshake ok; Toss returned FAIL (${m})` };
      }
      return { name: 'toss', state: 'red', detail: `mTLS or network failure: ${m}` };
    }
    return { name: 'toss', state: 'red', detail: (err as Error).message };
  }
}
```

The "FAIL is success" disambiguation is intentional and documented in the test: a doctor run without a real AT still proves the cert+key authenticate against Toss. If you have a real sandbox AT, the probe verifies the full path.

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Commit**

```bash
git add cli/commands/doctor-probes/toss-probe.ts cli/commands/doctor-probes/toss-probe.test.ts
git commit -m "feat(cli): doctor toss probe (optional, mTLS verify even with stub AT)"
```

---

## Task 8: `doctor` orchestrator + report

**Files:**
- Create: `cli/commands/doctor.ts`
- Test: `cli/commands/doctor.test.ts`

Aggregates all four (or five, with toss) probes into one `ProbeReport`. Overall status = worst of all items. Exit code: 0 if green, 0 if yellow, 1 if red. (Yellow is "warning, not failure" — important so CI smoke tests don't fail just because the toss probe was skipped.)

- [ ] **Step 1: Failing test**

```ts
// cli/commands/doctor.test.ts
import { describe, it, expect } from 'vitest';
import { runDoctor } from './doctor.js';

describe('runDoctor', () => {
  it('aggregates probes and returns worst state', async () => {
    const report = await runDoctor({
      probes: [
        async () => ({ name: 'a', state: 'green', detail: 'ok' }),
        async () => ({ name: 'b', state: 'yellow', detail: 'warn' }),
        async () => ({ name: 'c', state: 'green', detail: 'ok' }),
      ],
    });
    expect(report.status).toBe('yellow');
    expect(report.items.map((i) => i.name)).toEqual(['a', 'b', 'c']);
  });

  it('worst state is red when any probe is red', async () => {
    const report = await runDoctor({
      probes: [
        async () => ({ name: 'a', state: 'green', detail: 'ok' }),
        async () => ({ name: 'b', state: 'red', detail: 'broken' }),
      ],
    });
    expect(report.status).toBe('red');
  });

  it('captures probe throws as red items (no orchestrator crash)', async () => {
    const report = await runDoctor({
      probes: [
        async () => { throw new Error('boom'); },
        async () => ({ name: 'b', state: 'green', detail: 'ok' }),
      ],
    });
    expect(report.status).toBe('red');
    expect(report.items[0]).toMatchObject({ state: 'red', detail: 'boom' });
  });
});
```

- [ ] **Step 2: Run, expect failures**

- [ ] **Step 3: Implement**

```ts
// cli/commands/doctor.ts
import type { ProbeItem, ProbeReport, ProbeState } from '../output.js';

export interface DoctorOpts {
  probes: Array<() => Promise<ProbeItem>>;
}

const RANK: Record<ProbeState, number> = { green: 0, yellow: 1, red: 2 };

export async function runDoctor(opts: DoctorOpts): Promise<ProbeReport> {
  const items: ProbeItem[] = [];
  for (const probe of opts.probes) {
    try {
      items.push(await probe());
    } catch (err) {
      items.push({ name: 'unknown', state: 'red', detail: (err as Error).message });
    }
  }
  let worst: ProbeState = 'green';
  for (const item of items) {
    if (RANK[item.state] > RANK[worst]) worst = item.state;
  }
  return { status: worst, items };
}

export function exitCodeFor(report: ProbeReport): number {
  return report.status === 'red' ? 1 : 0;
}
```

- [ ] **Step 4: Run, expect green**

- [ ] **Step 5: Register the command in `cli/index.ts`**

```ts
program
  .command('doctor')
  .description('Run health probes against env, DB, master keys, JWKS, and (optionally) Toss sandbox.')
  .option('--cert <path>', 'sandbox mTLS cert PEM (enables Toss probe)')
  .option('--key <path>', 'sandbox mTLS key PEM (enables Toss probe)')
  .option('--access-token <token>', 'Toss access token (optional; without it, the probe still verifies mTLS handshake via FAIL envelope)')
  .option('--master-key-dir <dir>', 'master key directory (file provider)')
  .option('--json', 'force JSON output')
  .action(async (cmd) => {
    const env = process.env;
    const certPem = cmd.cert ? readFileSync(cmd.cert, 'utf8') : undefined;
    const keyPem = cmd.key ? readFileSync(cmd.key, 'utf8') : undefined;
    const signingKeys = collectSigningKeysFromEnv(env);
    const report = await runDoctor({
      probes: [
        async () => runEnvProbe(env),
        async () => runDbProbe({ dbUrl: env.BRIDGE_DB_URL ?? '' }),
        async () => runMasterKeyProbe({
          provider: (env.MASTER_KEY_PROVIDER as 'env' | 'file' | 'gcpsm') ?? 'env',
          masterKeyDir: cmd.masterKeyDir ?? env.MASTER_KEY_DIR,
          version: 1,
        }),
        async () => runJwksProbe({ activeKid: env.OIDC_ACTIVE_KID ?? '', signingKeys }),
        async () => runTossProbe({
          apiBase: env.TOSS_API_BASE ?? 'https://apps-in-toss-api.toss.im',
          certPem,
          keyPem,
          accessToken: cmd.accessToken,
        }),
      ],
    });
    createReporter({ stdout: process.stdout, forceJson: cmd.json === true }).report(report);
    process.exit(exitCodeFor(report));
  });
```

`collectSigningKeysFromEnv(env)` reads every `OIDC_SIGNING_KEY_<KID>_PEM` and returns `{ kid: pem }`. This helper exists in Phase 3's `signing-keys.ts`; import from there.

- [ ] **Step 6: Commit**

```bash
git add cli/commands/doctor.ts cli/commands/doctor.test.ts cli/index.ts
git commit -m "feat(cli): doctor orchestrator + register commands"
```

---

## Task 9: End-to-end smoke (bootstrap → doctor green-or-yellow)

**Files:**
- Create: `cli/commands/e2e.test.ts`

A single end-to-end test that runs `bootstrap` then `doctor` against the produced state and asserts the report is green or yellow (never red). This catches drift between the two commands' assumptions about the on-disk shape.

- [ ] **Step 1: Failing test**

```ts
// cli/commands/e2e.test.ts
import { describe, it, expect } from 'vitest';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { generateKeyPairSync } from 'node:crypto';
import { runBootstrap } from './bootstrap.js';
import { runDoctor } from './doctor.js';
import { runEnvProbe } from './doctor-probes/env-probe.js';
import { runDbProbe } from './doctor-probes/db-probe.js';
import { runMasterKeyProbe } from './doctor-probes/master-key-probe.js';
import { runJwksProbe } from './doctor-probes/jwks-probe.js';
import { runTossProbe } from './doctor-probes/toss-probe.js';

describe('bootstrap → doctor', () => {
  it('a freshly bootstrapped install passes doctor (green or yellow, never red)', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'bridge-e2e-'));
    const dbUrl = `sqlite://${join(dir, 'bridge.db')}`;
    const masterKeyDir = join(dir, 'keys');
    await runBootstrap({ dbUrl, masterKeyDir, email: 'a@b', workspaceName: 'w' });

    const { privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = privateKey.export({ type: 'pkcs8', format: 'pem' }) as string;

    const env: Record<string, string | undefined> = {
      BRIDGE_DB_URL: dbUrl,
      OIDC_ISSUER: 'https://oidc-bridge.aitc.dev',
      OIDC_ACTIVE_KID: 'k1',
      MASTER_KEY_PROVIDER: 'file',
      MASTER_KEY_DIR: masterKeyDir,
    };

    const report = await runDoctor({
      probes: [
        async () => runEnvProbe(env),
        async () => runDbProbe({ dbUrl }),
        async () => runMasterKeyProbe({ provider: 'file', masterKeyDir, version: 1 }),
        async () => runJwksProbe({ activeKid: 'k1', signingKeys: { k1: pem } }),
        async () => runTossProbe({ apiBase: 'https://x', certPem: undefined, keyPem: undefined }),
      ],
    });

    expect(report.status).not.toBe('red');
    // Toss probe is yellow (no cert), env+db+master-key+jwks should all be green.
    const tossItem = report.items.find((i) => i.name === 'toss')!;
    expect(tossItem.state).toBe('yellow');
    for (const item of report.items) {
      if (item.name !== 'toss') expect(item.state).toBe('green');
    }
  });
});
```

- [ ] **Step 2: Run, expect green** (everything is already implemented; this is an integration test that reuses Tasks 2–8)

- [ ] **Step 3: Commit**

```bash
git add cli/commands/e2e.test.ts
git commit -m "test(cli): bootstrap→doctor e2e (green-or-yellow contract)"
```

---

## Task 10: SELF_HOSTING.md walkthrough

**Files:**
- Create: `docs/SELF_HOSTING.md` (or modify if Phase 9 already stubbed it)
- Modify: `docs/RUNBOOK.md` to point at SELF_HOSTING.md for first-time setup

- [ ] **Step 1: Author SELF_HOSTING.md**

```markdown
# Self-hosting oidc-bridge

This guide takes you from an empty machine to a working OIDC bridge.

## Prerequisites

- Node 24 (`node --version` → v24.x).
- pnpm 10 (`pnpm --version` → 10.x).
- A directory you control for the SQLite DB and master key file (e.g.
  `/var/lib/bridge/`).
- Optional: a Toss sandbox cert + key for the `doctor` Toss probe.

## 1. Install

```bash
git clone https://github.com/apps-in-toss-community/oidc-bridge.git
cd oidc-bridge
pnpm install
pnpm build
```

## 2. Bootstrap

```bash
pnpm bridge bootstrap \
  --db sqlite:///var/lib/bridge/bridge.db \
  --master-key-dir /var/lib/bridge/keys \
  --email you@example.com \
  --workspace default \
  --issuer-hint https://oidc.your-domain.example
```

Output ends with a printable summary including your one-time API token.
Copy it now; it cannot be recovered.

The on-disk artefacts are:

- `/var/lib/bridge/bridge.db` — SQLite, mode 644 (default).
- `/var/lib/bridge/keys/v1.key` — 32 raw bytes, mode 600.

## 3. Configure

Generate the OIDC RSA-2048 signing keypair (one-time):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out signing-k1.pem
```

Save it as the env var `OIDC_SIGNING_KEY_K1_PEM`.

Minimum `.env`:

```bash
BRIDGE_DB_URL=sqlite:///var/lib/bridge/bridge.db
MASTER_KEY_PROVIDER=file
MASTER_KEY_DIR=/var/lib/bridge/keys
OIDC_ISSUER=https://oidc.your-domain.example
OIDC_ACTIVE_KID=k1
OIDC_SIGNING_KEY_K1_PEM="-----BEGIN PRIVATE KEY-----
... (paste the contents of signing-k1.pem) ...
-----END PRIVATE KEY-----"
```

## 4. Doctor

```bash
pnpm bridge doctor
```

Expected: 5 rows. Four green (env / db / master-key / jwks). One yellow
(toss — skipped, no sandbox cert provided). Report status = `yellow`,
exit code = `0`.

If you have a sandbox cert:

```bash
pnpm bridge doctor --cert /path/to/sandbox.cert.pem --key /path/to/sandbox.key.pem
```

The toss row turns green if the cert authenticates against Toss (even
without a real access token — the probe accepts a `FAIL` envelope as
proof of mTLS handshake).

## 5. Run

```bash
pnpm start
```

Default port: `8080`. Behind your reverse proxy (Caddy / nginx /
Traefik), terminate TLS and forward to `:8080`.

Verify discovery:

```bash
curl https://oidc.your-domain.example/.well-known/openid-configuration
```

Should return JSON with your `issuer`.

## 6. Register your first app

Use the Admin REST API with the bootstrap API token:

```bash
ADMIN_API_TOKEN=bait_xxxx.yyyyyyy ./scripts/register-app.sh
```

(See [`docs/admin/REGISTERING_AN_APP.md`](./admin/REGISTERING_AN_APP.md))

## 7. Updating

`pnpm install && pnpm build && systemctl restart oidc-bridge`. Migrations
run on next startup. Master key file unaffected. Add new signing keys by
appending `OIDC_SIGNING_KEY_K2_PEM=...` and bumping `OIDC_ACTIVE_KID=k2`
when you want to start signing with the new one.

## Backups

Two files matter:

- The SQLite DB (`/var/lib/bridge/bridge.db`).
- The master key file (`/var/lib/bridge/keys/v1.key`).

Without the master key file, the encrypted columns in the DB are
unrecoverable. Snapshot both atomically (e.g. `cp` while the bridge is
stopped, or `sqlite3 .backup` while it runs).
```

- [ ] **Step 2: Update RUNBOOK pointer**

In `docs/RUNBOOK.md`, replace any "first-time setup" section with a one-line pointer:

```markdown
## First-time self-host setup

See [`SELF_HOSTING.md`](./SELF_HOSTING.md). The `pnpm bridge bootstrap`
command is the canonical entry point.
```

- [ ] **Step 3: Commit**

```bash
git add docs/SELF_HOSTING.md docs/RUNBOOK.md
git commit -m "docs: SELF_HOSTING.md walkthrough; RUNBOOK pointers"
```

---

## Task 11: Final verification + open PR

**Files:** none.

- [ ] **Step 1: Full local check**

```bash
pnpm typecheck
pnpm lint
pnpm test
```

All green.

- [ ] **Step 2: Run the commands by hand**

```bash
TMP=$(mktemp -d)
pnpm bridge bootstrap \
  --db "sqlite://${TMP}/bridge.db" \
  --master-key-dir "${TMP}/keys" \
  --email you@example.com \
  --workspace default
# Copy the printed ADMIN_API_TOKEN.

# Generate a throwaway signing key.
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out "${TMP}/k1.pem" 2>/dev/null

BRIDGE_DB_URL="sqlite://${TMP}/bridge.db" \
MASTER_KEY_PROVIDER=file \
MASTER_KEY_DIR="${TMP}/keys" \
OIDC_ISSUER=https://oidc-bridge.aitc.dev \
OIDC_ACTIVE_KID=k1 \
OIDC_SIGNING_KEY_K1_PEM="$(cat ${TMP}/k1.pem)" \
pnpm bridge doctor
```

Expected: 5 rows, four green, one yellow (toss). Exit code 0.

- [ ] **Step 3: Push + open PR**

```bash
git push -u origin feat/zero-code-phase-07
gh pr create \
  --base main \
  --title "feat: zero-code Phase 7 — bootstrap + doctor CLIs" \
  --body "$(cat <<'EOF'
## Summary
- `pnpm bridge bootstrap` produces a fresh sqlite-backed self-host install end to end (DB + master key file + first user + first API token + first workspace).
- `pnpm bridge doctor` runs five probes (env, db, master-key, jwks, optional toss) and reports green / yellow / red.
- TTY-aware reporter writes JSON for non-TTY stdout.
- Toss probe accepts a `FAIL` envelope as proof of mTLS handshake even without a real AT.
- `docs/SELF_HOSTING.md` is the canonical onboarding walkthrough.

## Test plan
- [ ] `pnpm test` green; `pnpm test cli/` runs all probe tests.
- [ ] `bootstrap → doctor` e2e test passes (yellow overall, four greens, toss yellow).
- [ ] Manual run with a sandbox cert turns the toss probe green.
EOF
)"
```

- [ ] **Step 4: Wait for CI green and merge.**

---

## Done condition

- `pnpm bridge bootstrap` produces a self-contained install in one command.
- `pnpm bridge doctor` reports the install state in a few seconds, with a stable JSON shape for non-TTY stdout.
- The five probes cover env, DB, master keys, JWKS, and (optionally) Toss mTLS.
- A fresh bootstrap → doctor run is green-or-yellow, never red. The e2e test pins this contract.
- Self-hosting walkthrough in `docs/SELF_HOSTING.md` matches what the CLI actually does — no aspirational docs.

That state is the foundation Phase 8 (status page + rate-limit + observability) builds on — Phase 8 reuses the doctor's probe shape (`{ name, state, detail }`) for the runtime `/status` page, so the same probes can be polled from a running bridge as easily as a CLI.
