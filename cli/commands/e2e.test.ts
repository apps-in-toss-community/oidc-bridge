import { generateKeyPairSync } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { runBootstrap } from './bootstrap.js';
import { runDoctor } from './doctor.js';
import { runDbProbe } from './doctor-probes/db-probe.js';
import { runEnvProbe } from './doctor-probes/env-probe.js';
import { runJwksProbe } from './doctor-probes/jwks-probe.js';
import { runMasterKeyProbe } from './doctor-probes/master-key-probe.js';
import { runTossProbe } from './doctor-probes/toss-probe.js';

describe('bootstrap → doctor e2e', () => {
  let workDir: string;

  beforeEach(() => {
    workDir = mkdtempSync(join(tmpdir(), 'oidc-bridge-e2e-'));
  });

  afterEach(() => {
    rmSync(workDir, { recursive: true, force: true });
  });

  it('a fresh bootstrap produces an install that doctor reports as green-or-yellow (never red)', async () => {
    const dbPath = join(workDir, 'data', 'oidc-bridge.sqlite');
    const masterKeyDir = join(workDir, 'mkeys');

    // 1. Bootstrap a fresh install.
    const summary = await runBootstrap({
      dbPath,
      masterKeyDir,
      email: 'op@example.com',
      workspaceName: 'first',
    });
    expect(summary.apiTokenPlaintext).toMatch(/^tok_/);
    expect(summary.userId).toMatch(/^user_/);
    expect(summary.workspaceId).toMatch(/^ws_/);
    expect(summary.masterKeyVersion).toBe(1);

    // 2. Generate a signing key the doctor can verify with.
    const { privateKey } = generateKeyPairSync('rsa', {
      modulusLength: 2048,
      privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
      publicKeyEncoding: { type: 'spki', format: 'pem' },
    });

    // 3. Build the env that mirrors what bootstrap tells the operator to set.
    const env: Record<string, string | undefined> = {
      OIDC_ISSUER: 'https://oidc-bridge.example',
      OIDC_ACTIVE_KID: 'k1',
      OIDC_SIGNING_KEY_K1_PEM: privateKey,
      STORAGE: 'sqlite',
      SQLITE_PATH: dbPath,
      MASTER_KEY_PROVIDER: 'file',
      MASTER_KEY_DIR: masterKeyDir,
    };

    // 4. Run the doctor probes against that install. Toss is skipped (yellow)
    //    because no sandbox cert/key is supplied — that's expected.
    const report = await runDoctor({
      probes: [
        async () => runEnvProbe(env),
        async () => runDbProbe({ storage: 'sqlite', sqlitePath: dbPath }),
        async () => runMasterKeyProbe({ provider: 'file', masterKeyDir, version: 1 }),
        async () =>
          runJwksProbe({
            activeKid: 'k1',
            signingKeys: { k1: privateKey },
          }),
        async () =>
          runTossProbe({
            apiBase: 'https://apps-in-toss-api.toss.im',
            certPem: undefined,
            keyPem: undefined,
          }),
      ],
    });

    expect(report.status).not.toBe('red');
    const byName = Object.fromEntries(report.items.map((i) => [i.name, i]));
    expect(byName.env?.state).toBe('green');
    expect(byName.db?.state).toBe('green'); // bootstrap pre-created the file
    expect(byName['master-key']?.state).toBe('green');
    expect(byName.jwks?.state).toBe('green');
    expect(byName.toss?.state).toBe('yellow');
  });

  it('refuses to overwrite an existing master key on second bootstrap', async () => {
    const dbPath = join(workDir, 'data', 'oidc-bridge.sqlite');
    const masterKeyDir = join(workDir, 'mkeys');
    await runBootstrap({
      dbPath,
      masterKeyDir,
      email: 'op@example.com',
      workspaceName: 'first',
    });
    await expect(
      runBootstrap({
        dbPath: join(workDir, 'data', 'second.sqlite'),
        masterKeyDir,
        email: 'op2@example.com',
        workspaceName: 'second',
      }),
    ).rejects.toThrow(/master key already exists/);
  });
});
