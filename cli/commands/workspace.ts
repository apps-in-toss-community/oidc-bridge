import { Command } from 'commander';
import { type ConnectionOptions, close, connect } from './_shared.js';

interface WorkspaceJson {
  id: string;
  name: string;
}

export function workspaceCommand(): Command {
  const cmd = new Command('workspace').description('manage workspaces');

  cmd
    .command('list')
    .description('list workspaces')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions) => {
      const c = connect(opts);
      try {
        const list =
          c.mode === 'offline'
            ? await c.service.workspaces.list(c.ctx)
            : await c.client.request<WorkspaceJson[]>('GET', '/admin/workspaces');
        for (const w of list) {
          console.log(`${w.id}\t${w.name}`);
        }
      } finally {
        await close(c);
      }
    });

  cmd
    .command('create')
    .description('create a workspace')
    .requiredOption('--name <name>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { name: string }) => {
      const c = connect(opts);
      try {
        const w =
          c.mode === 'offline'
            ? await c.service.workspaces.create(c.ctx, { name: opts.name })
            : await c.client.request<WorkspaceJson>('POST', '/admin/workspaces', {
                name: opts.name,
              });
        console.log(`${w.id}\t${w.name}`);
      } finally {
        await close(c);
      }
    });

  cmd
    .command('rename')
    .description('rename a workspace')
    .requiredOption('--id <id>')
    .requiredOption('--name <name>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string; name: string }) => {
      const c = connect(opts);
      try {
        const w =
          c.mode === 'offline'
            ? await c.service.workspaces.update(c.ctx, opts.id, { name: opts.name })
            : await c.client.request<WorkspaceJson>('PATCH', `/admin/workspaces/${opts.id}`, {
                name: opts.name,
              });
        console.log(`${w.id}\t${w.name}`);
      } finally {
        await close(c);
      }
    });

  cmd
    .command('delete')
    .description('delete a workspace')
    .requiredOption('--id <id>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string }) => {
      const c = connect(opts);
      try {
        if (c.mode === 'offline') {
          await c.service.workspaces.delete(c.ctx, opts.id);
        } else {
          await c.client.request('DELETE', `/admin/workspaces/${opts.id}`);
        }
        console.log(`deleted ${opts.id}`);
      } finally {
        await close(c);
      }
    });

  return cmd;
}
