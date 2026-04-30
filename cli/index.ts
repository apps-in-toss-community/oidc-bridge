#!/usr/bin/env node
import { Command } from 'commander';
import { tenantCreate } from './commands/tenant-create.js';
import { tenantDelete } from './commands/tenant-delete.js';
import { tenantList } from './commands/tenant-list.js';
import { tenantRotateSecret } from './commands/tenant-rotate-secret.js';
import { tenantShow } from './commands/tenant-show.js';

const program = new Command();
program
  .name('oidc-bridge')
  .description('CLI for the apps-in-toss-community OIDC bridge')
  .option('--bridge <url>', 'bridge base URL', process.env.OIDC_BRIDGE_URL)
  .option('--admin-token <t>', 'admin token', process.env.ADMIN_TOKEN)
  .option('--offline', 'talk directly to fs-store on disk (no running bridge)')
  .option('--data-dir <path>', 'fs-store data dir (offline mode)', process.env.BRIDGE_DATA_DIR);

const tenant = program.command('tenant').description('Tenant management');
tenant
  .command('create')
  .requiredOption('--name <name>')
  .requiredOption('--environment <env>')
  .requiredOption('--cert <path>')
  .requiredOption('--key <path>')
  .action(
    (opts: { name: string; environment: 'production' | 'sandbox'; cert: string; key: string }) =>
      tenantCreate(program.opts(), opts),
  );
tenant.command('list').action(() => tenantList(program.opts()));
tenant
  .command('show')
  .argument('<id>')
  .action((id: string) => tenantShow(program.opts(), id));
tenant
  .command('rotate-secret')
  .argument('<id>')
  .action((id: string) => tenantRotateSecret(program.opts(), id));
tenant
  .command('delete')
  .argument('<id>')
  .action((id: string) => tenantDelete(program.opts(), id));

program.parseAsync().catch((err: unknown) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
