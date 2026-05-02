import { Command } from 'commander';
import { type ConnectionOptions, close, connect } from './_shared.js';

interface ApiTokenJson {
  id: string;
  name: string;
  scopes: string[];
}

export function apiTokenCommand(): Command {
  const cmd = new Command('api-token').description('manage api tokens');

  cmd
    .command('create')
    .description('create an api token')
    .requiredOption('--name <name>')
    .option('--scope <scope...>', 'scope (repeatable)', [])
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { name: string; scope: string[] }) => {
      const c = connect(opts);
      try {
        if (c.mode === 'offline') {
          const r = await c.service.apiTokens.create(c.ctx, {
            name: opts.name,
            scopes: opts.scope,
          });
          console.log(`${r.token.id}\t${r.token.name}`);
          console.log(`token: ${r.plaintext}`);
          console.log('(this is the only time the plaintext token will be shown)');
        } else {
          const r = await c.client.request<{ token: ApiTokenJson; plaintext: string }>(
            'POST',
            '/admin/api-tokens',
            { name: opts.name, scopes: opts.scope },
          );
          console.log(`${r.token.id}\t${r.token.name}`);
          console.log(`token: ${r.plaintext}`);
          console.log('(this is the only time the plaintext token will be shown)');
        }
      } finally {
        await close(c);
      }
    });

  cmd
    .command('list')
    .description('list api tokens')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions) => {
      const c = connect(opts);
      try {
        const list =
          c.mode === 'offline'
            ? await c.service.apiTokens.list(c.ctx)
            : await c.client.request<ApiTokenJson[]>('GET', '/admin/api-tokens');
        for (const t of list) {
          console.log(`${t.id}\t${t.name}\t${t.scopes.join(',')}`);
        }
      } finally {
        await close(c);
      }
    });

  cmd
    .command('delete')
    .description('delete an api token')
    .requiredOption('--id <id>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string }) => {
      const c = connect(opts);
      try {
        if (c.mode === 'offline') await c.service.apiTokens.delete(c.ctx, opts.id);
        else await c.client.request('DELETE', `/admin/api-tokens/${opts.id}`);
        console.log(`deleted ${opts.id}`);
      } finally {
        await close(c);
      }
    });

  return cmd;
}
