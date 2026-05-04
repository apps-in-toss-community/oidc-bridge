import { randomBytes } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import bcrypt from 'bcryptjs';
import { Command } from 'commander';
import { createService } from '../../src/apps/service.js';
import { newId } from '../../src/ids.js';
import { createSqliteStorage } from '../../src/storage/sqlite.js';

const BCRYPT_ROUNDS = 12;
const MASTER_KEY_BYTES = 32;
const MASTER_KEY_VERSION = 1;

export interface BootstrapOpts {
  dbPath: string;
  masterKeyDir: string;
  email: string;
  workspaceName: string;
  password?: string;
}

export interface BootstrapSummary {
  userId: string;
  workspaceId: string;
  apiTokenId: string;
  apiTokenPlaintext: string;
  masterKeyVersion: number;
  masterKeyPath: string;
}

export async function runBootstrap(opts: BootstrapOpts): Promise<BootstrapSummary> {
  // Validate master-key path early so we don't open a DB just to back out.
  const masterKeyPath = join(opts.masterKeyDir, `v${MASTER_KEY_VERSION}.key`);
  if (existsSync(masterKeyPath)) {
    throw new Error(
      `bootstrap: master key already exists at ${masterKeyPath}; refusing to overwrite`,
    );
  }

  // Ensure DB parent dir exists so sqlite can create the file.
  mkdirSync(dirname(opts.dbPath), { recursive: true });

  const storage = createSqliteStorage({ path: opts.dbPath });
  try {
    const existingByEmail = await storage.getUserByEmail(opts.email);
    if (existingByEmail) {
      throw new Error('bootstrap: this DB is already bootstrapped (users table not empty)');
    }
    // Belt + braces: refuse if the master_keys table already has v1.
    const existingMk = await storage.getMasterKeyByVersion(MASTER_KEY_VERSION);
    if (existingMk) {
      throw new Error('bootstrap: this DB is already bootstrapped (users table not empty)');
    }

    // Write the master-key file (v1.key, 32 random bytes, mode 600).
    mkdirSync(opts.masterKeyDir, { recursive: true });
    writeFileSync(masterKeyPath, randomBytes(MASTER_KEY_BYTES), { mode: 0o600 });
    chmodSync(masterKeyPath, 0o600);

    // Master-key metadata row (no bytes!).
    await storage.createMasterKey({
      id: newId('master_key'),
      version: MASTER_KEY_VERSION,
      providerRef: `file:${masterKeyPath}`,
    });

    // First user.
    const userId = newId('user');
    const user = await storage.createUser({ id: userId, email: opts.email });
    if (opts.password) {
      const hash = await bcrypt.hash(opts.password, BCRYPT_ROUNDS);
      await storage.setUserPassword(user.id, hash);
    }

    // Workspace + API token via the service so audit-log entries are written
    // and api-token plaintext goes through the same generator the rest of the
    // codebase verifies against.
    const service = createService({ storage });
    const ctx = { actorUserId: user.id };
    const ws = await service.workspaces.create(ctx, { name: opts.workspaceName });
    const tok = await service.apiTokens.create(ctx, { name: 'bootstrap', scopes: ['admin'] });

    return {
      userId: user.id,
      workspaceId: ws.id,
      apiTokenId: tok.token.id,
      apiTokenPlaintext: tok.plaintext,
      masterKeyVersion: MASTER_KEY_VERSION,
      masterKeyPath,
    };
  } finally {
    await storage.close();
  }
}

export function formatBootstrapSummary(
  s: BootstrapSummary,
  env: { issuerHint: string; dbPath: string },
): string {
  return [
    '',
    'Bootstrap complete.',
    '',
    'Save these values now — the API token plaintext will not be shown again.',
    '',
    `  USER_ID=${s.userId}`,
    `  WORKSPACE_ID=${s.workspaceId}`,
    `  API_TOKEN_ID=${s.apiTokenId}`,
    `  ADMIN_API_TOKEN=${s.apiTokenPlaintext}`,
    `  MASTER_KEY_PATH=${s.masterKeyPath}  (mode 600)`,
    '',
    'Add to your bridge .env:',
    '',
    '  STORAGE=sqlite',
    `  SQLITE_PATH=${env.dbPath}`,
    '  MASTER_KEY_PROVIDER=file',
    `  MASTER_KEY_DIR=${s.masterKeyPath.replace(/\/v1\.key$/, '')}`,
    `  OIDC_ISSUER=${env.issuerHint}`,
    '  OIDC_ACTIVE_KID=k1',
    '  OIDC_SIGNING_KEY_K1_PEM="$(cat your-signing-key.pem)"',
    '  API_TOKEN=<paste ADMIN_API_TOKEN above>',
    '',
    'Next: run `oidc-bridge doctor` to verify the install.',
    '',
  ].join('\n');
}

export function bootstrapCommand(): Command {
  return new Command('bootstrap')
    .description('Initialize a fresh self-host install (sqlite only)')
    .requiredOption('--db-path <path>', 'sqlite database path (created if missing)')
    .requiredOption('--master-key-dir <dir>', 'directory for master-key files (created if missing)')
    .requiredOption('--email <email>', 'first user email')
    .option('--workspace <name>', 'first workspace name', 'default')
    .option('--password <password>', 'set users.password_hash for the new user (optional)')
    .option(
      '--issuer-hint <url>',
      'shown in the printed env summary',
      'https://oidc-bridge.example',
    )
    .action(
      async (cmd: {
        dbPath: string;
        masterKeyDir: string;
        email: string;
        workspace: string;
        password?: string;
        issuerHint: string;
      }) => {
        const summary = await runBootstrap({
          dbPath: cmd.dbPath,
          masterKeyDir: cmd.masterKeyDir,
          email: cmd.email,
          workspaceName: cmd.workspace,
          ...(cmd.password !== undefined ? { password: cmd.password } : {}),
        });
        process.stdout.write(
          formatBootstrapSummary(summary, { issuerHint: cmd.issuerHint, dbPath: cmd.dbPath }),
        );
      },
    );
}
