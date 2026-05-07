import { readFileSync } from 'node:fs';
import { Command } from 'commander';
import { createMasterKeyProvider } from '../../src/master-keys/index.js';
import { type ConnectionOptions, close, connect } from './_shared.js';

interface AppJson {
  id: string;
  appIdToss: string;
  displayTitle: string;
  clientId: string;
  ownershipStatus: string;
  rawTokensEnabled: boolean;
}
interface CreateAppResponse {
  app: AppJson;
  clientId: string;
  clientSecret: string;
}

export function appCommand(): Command {
  const cmd = new Command('app').description('manage apps');

  cmd
    .command('create')
    .description('create an app')
    .requiredOption('--workspace-id <id>')
    .requiredOption('--app-id-toss <id>', 'the Toss mini-app ID')
    .requiredOption('--title <title>')
    .requiredOption('--cert <path>', 'path to mTLS certificate PEM')
    .requiredOption('--key <path>', 'path to mTLS private key PEM')
    .option('--allowed-origin <url...>', 'allowed origin (repeatable)', [])
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .option('--master-key-version <n>', 'sealing key version for offline mode', '1')
    .option('--stage <stage>', 'alpha|beta|ga', 'alpha')
    .action(
      async (
        opts: ConnectionOptions & {
          workspaceId: string;
          appIdToss: string;
          title: string;
          cert: string;
          key: string;
          allowedOrigin: string[];
          masterKeyVersion: string;
          stage: string;
        },
      ) => {
        const certPem = readFileSync(opts.cert, 'utf8');
        const keyPem = readFileSync(opts.key, 'utf8');
        const c = connect(opts);
        try {
          if (c.mode === 'offline') {
            const provider = createMasterKeyProvider();
            const version = Number(opts.masterKeyVersion);
            const masterKey = await provider.getKeyBytes(version);
            const r = await c.service.apps.create(c.ctx, {
              workspaceId: opts.workspaceId,
              appIdToss: opts.appIdToss,
              displayTitle: opts.title,
              mtlsCert: new TextEncoder().encode(certPem),
              mtlsKey: new TextEncoder().encode(keyPem),
              allowedOrigins: opts.allowedOrigin,
              sealingKeyVersion: version,
              masterKey,
              stage: opts.stage as 'alpha' | 'beta' | 'ga',
            });
            console.log(`${r.app.id}\t${r.clientId}`);
            console.log(`client_secret: ${r.clientSecret}`);
            console.log('(this is the only time the plaintext secret will be shown)');
          } else {
            const r = await c.client.request<CreateAppResponse>(
              'POST',
              `/admin/workspaces/${opts.workspaceId}/apps`,
              {
                appIdToss: opts.appIdToss,
                displayTitle: opts.title,
                mtlsCertPem: certPem,
                mtlsKeyPem: keyPem,
                allowedOrigins: opts.allowedOrigin,
              },
            );
            console.log(`${r.app.id}\t${r.clientId}`);
            console.log(`client_secret: ${r.clientSecret}`);
            console.log('(this is the only time the plaintext secret will be shown)');
          }
        } finally {
          await close(c);
        }
      },
    );

  cmd
    .command('list')
    .description('list apps in a workspace')
    .requiredOption('--workspace-id <id>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { workspaceId: string }) => {
      const c = connect(opts);
      try {
        const list =
          c.mode === 'offline'
            ? await c.service.apps.list(c.ctx, opts.workspaceId)
            : await c.client.request<AppJson[]>(
                'GET',
                `/admin/workspaces/${opts.workspaceId}/apps`,
              );
        for (const a of list) {
          console.log(`${a.id}\t${a.appIdToss}\t${a.displayTitle}\t${a.ownershipStatus}`);
        }
      } finally {
        await close(c);
      }
    });

  cmd
    .command('rotate-secret')
    .description("rotate an app's client_secret")
    .requiredOption('--id <id>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string }) => {
      const c = connect(opts);
      try {
        const r =
          c.mode === 'offline'
            ? await c.service.apps.rotateSecret(c.ctx, opts.id)
            : await c.client.request<{ app: AppJson; clientSecret: string }>(
                'POST',
                `/admin/apps/${opts.id}/secrets/rotate`,
              );
        console.log(`client_secret: ${r.clientSecret}`);
        console.log('(this is the only time the plaintext secret will be shown)');
      } finally {
        await close(c);
      }
    });

  cmd
    .command('toggle-raw-tokens')
    .description('enable or disable raw-tokens endpoint for an app')
    .requiredOption('--id <id>')
    .requiredOption('--enabled <bool>', 'true|false')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string; enabled: string }) => {
      const enabled = opts.enabled === 'true';
      const c = connect(opts);
      try {
        const a =
          c.mode === 'offline'
            ? await c.service.apps.toggleRawTokens(c.ctx, opts.id, enabled)
            : await c.client.request<AppJson>('POST', `/admin/apps/${opts.id}/raw-tokens`, {
                enabled,
              });
        console.log(`raw_tokens_enabled = ${a.rawTokensEnabled}`);
      } finally {
        await close(c);
      }
    });

  cmd
    .command('delete')
    .description('delete an app')
    .requiredOption('--id <id>')
    .option('--api-url <url>')
    .option('--token <token>')
    .option('--db-path <path>')
    .option('--as-user <userId>')
    .action(async (opts: ConnectionOptions & { id: string }) => {
      const c = connect(opts);
      try {
        if (c.mode === 'offline') await c.service.apps.delete(c.ctx, opts.id);
        else await c.client.request('DELETE', `/admin/apps/${opts.id}`);
        console.log(`deleted ${opts.id}`);
      } finally {
        await close(c);
      }
    });

  return cmd;
}
