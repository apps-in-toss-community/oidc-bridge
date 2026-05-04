import { randomBytes } from 'node:crypto';
import bcrypt from 'bcryptjs';
import { Command } from 'commander';
import { createSqliteStorage } from '../../src/storage/sqlite.js';

const BCRYPT_ROUNDS = 12;

export interface SetUserPasswordOpts {
  dbPath: string;
  email: string;
  password: string;
}

export async function setUserPasswordOffline(opts: SetUserPasswordOpts): Promise<void> {
  if (!opts.password) throw new Error('password must not be empty');
  const storage = createSqliteStorage({ path: opts.dbPath });
  try {
    const user = await storage.getUserByEmail(opts.email);
    if (!user) throw new Error(`no user with email ${opts.email}`);
    const hash = await bcrypt.hash(opts.password, BCRYPT_ROUNDS);
    await storage.setUserPassword(user.id, hash);
  } finally {
    await storage.close();
  }
}

export interface CreateUserOfflineOpts {
  dbPath: string;
  email: string;
  id?: string;
}

export async function createUserOffline(
  opts: CreateUserOfflineOpts,
): Promise<{ id: string; email: string }> {
  const id = opts.id ?? randomBytes(16).toString('hex');
  const storage = createSqliteStorage({ path: opts.dbPath });
  try {
    const existing = await storage.getUserByEmail(opts.email);
    if (existing) throw new Error(`user already exists: ${opts.email}`);
    const user = await storage.createUser({ id, email: opts.email });
    return { id: user.id, email: user.email };
  } finally {
    await storage.close();
  }
}

function readPasswordFromStdin(): Promise<string> {
  return new Promise((resolve, reject) => {
    let buf = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      buf += chunk;
    });
    process.stdin.on('end', () => resolve(buf.replace(/\r?\n$/, '')));
    process.stdin.on('error', reject);
  });
}

export function userCommand(): Command {
  const cmd = new Command('user').description('manage users');

  cmd
    .command('create <email>')
    .description('create a user (offline; sqlite only)')
    .requiredOption('--db-path <path>', 'path to the sqlite database')
    .option('--id <id>', 'explicit user id (default: random 32-hex)')
    .action(async (email: string, opts: { dbPath: string; id?: string }) => {
      const createOpts: CreateUserOfflineOpts = { dbPath: opts.dbPath, email };
      if (opts.id !== undefined) createOpts.id = opts.id;
      const u = await createUserOffline(createOpts);
      console.log(`user created: id=${u.id} email=${u.email}`);
    });

  cmd
    .command('set-password <email>')
    .description('set a user password (offline; sqlite only)')
    .requiredOption('--db-path <path>', 'path to the sqlite database')
    .option(
      '--password <password>',
      'password (omit to read one line from stdin; recommended for scripts)',
    )
    .action(async (email: string, opts: { dbPath: string; password?: string }) => {
      const password = opts.password ?? (await readPasswordFromStdin());
      await setUserPasswordOffline({ dbPath: opts.dbPath, email, password });
      console.log(`password set for ${email}`);
    });

  return cmd;
}
