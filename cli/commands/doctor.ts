import { readFileSync } from 'node:fs';
import { Command } from 'commander';
import { createReporter, type ProbeItem, type ProbeReport, type ProbeState } from '../output.js';
import { runDbProbe } from './doctor-probes/db-probe.js';
import { runEnvProbe } from './doctor-probes/env-probe.js';
import { runJwksProbe } from './doctor-probes/jwks-probe.js';
import { runMasterKeyProbe } from './doctor-probes/master-key-probe.js';
import { runTossProbe } from './doctor-probes/toss-probe.js';

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

function collectSigningKeysFromEnv(env: NodeJS.ProcessEnv): Record<string, string> {
  const out: Record<string, string> = {};
  const prefix = 'OIDC_SIGNING_KEY_';
  const suffix = '_PEM';
  for (const [k, v] of Object.entries(env)) {
    if (!v || !k.startsWith(prefix) || !k.endsWith(suffix)) continue;
    const kid = k.slice(prefix.length, -suffix.length).toLowerCase();
    out[kid] = v;
  }
  return out;
}

export function doctorCommand(): Command {
  return new Command('doctor')
    .description(
      'Run health probes against env, DB, master keys, JWKS, and (optionally) Toss sandbox.',
    )
    .option('--cert <path>', 'sandbox mTLS cert PEM (enables Toss probe)')
    .option('--key <path>', 'sandbox mTLS key PEM (enables Toss probe)')
    .option(
      '--access-token <token>',
      'Toss access token (optional; without it the probe still verifies mTLS via FAIL envelope)',
    )
    .option('--master-key-dir <dir>', 'master key directory (file provider override)')
    .option('--json', 'force JSON output')
    .action(
      async (cmd: {
        cert?: string;
        key?: string;
        accessToken?: string;
        masterKeyDir?: string;
        json?: boolean;
      }) => {
        const env = process.env;
        const certPem = cmd.cert ? readFileSync(cmd.cert, 'utf8') : undefined;
        const keyPem = cmd.key ? readFileSync(cmd.key, 'utf8') : undefined;
        const signingKeys = collectSigningKeysFromEnv(env);
        const activeKid = (env.OIDC_ACTIVE_KID ?? '').toLowerCase();
        const storageKind = (env.STORAGE ?? 'sqlite').toLowerCase();
        const provider = (env.MASTER_KEY_PROVIDER ?? 'env') as 'env' | 'file' | 'gcpsm';
        const masterKeyDir = cmd.masterKeyDir ?? env.MASTER_KEY_DIR;

        const report = await runDoctor({
          probes: [
            async () => runEnvProbe(env),
            async () =>
              storageKind === 'pg'
                ? runDbProbe({ storage: 'pg', connectionString: env.DATABASE_URL ?? '' })
                : runDbProbe({
                    storage: 'sqlite',
                    sqlitePath: env.SQLITE_PATH ?? './data/oidc-bridge.sqlite',
                  }),
            async () =>
              runMasterKeyProbe({
                provider,
                ...(masterKeyDir !== undefined ? { masterKeyDir } : {}),
                version: 1,
              }),
            async () => runJwksProbe({ activeKid, signingKeys }),
            async () =>
              runTossProbe({
                apiBase: env.TOSS_API_BASE ?? 'https://apps-in-toss-api.toss.im',
                certPem,
                keyPem,
                ...(cmd.accessToken !== undefined ? { accessToken: cmd.accessToken } : {}),
              }),
          ],
        });
        createReporter({ stdout: process.stdout, forceJson: cmd.json === true }).report(report);
        process.exit(exitCodeFor(report));
      },
    );
}
