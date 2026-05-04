#!/usr/bin/env node
import { Command } from 'commander';
import { apiTokenCommand } from './commands/api-token.js';
import { appCommand } from './commands/app.js';
import { userCommand } from './commands/user.js';
import { workspaceCommand } from './commands/workspace.js';

const program = new Command()
  .name('oidc-bridge')
  .description('oidc-bridge admin CLI')
  .version('0.0.0');

program.addCommand(workspaceCommand());
program.addCommand(appCommand());
program.addCommand(apiTokenCommand());
program.addCommand(userCommand());

program.parseAsync(process.argv).catch((err) => {
  console.error(err instanceof Error ? err.message : err);
  process.exit(1);
});
