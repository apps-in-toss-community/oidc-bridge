import { createEnvMasterKeyProvider } from '../../../src/master-keys/env-provider.js';
import { createFileMasterKeyProvider } from '../../../src/master-keys/file-provider.js';
import type { ProbeItem } from '../../output.js';

export interface MasterKeyProbeOpts {
  provider: 'env' | 'file' | 'gcpsm';
  masterKeyDir?: string | undefined;
  version: number;
  env?: Record<string, string | undefined>;
}

export async function runMasterKeyProbe(opts: MasterKeyProbeOpts): Promise<ProbeItem> {
  if (opts.provider === 'gcpsm') {
    return {
      name: 'master-key',
      state: 'yellow',
      detail: 'gcpsm provider not exercised by doctor (manual verify in cloud)',
    };
  }
  if (opts.provider === 'file') {
    return runFileProbe(opts);
  }
  return runEnvProbe(opts);
}

async function runFileProbe(opts: MasterKeyProbeOpts): Promise<ProbeItem> {
  if (!opts.masterKeyDir) {
    return {
      name: 'master-key',
      state: 'red',
      detail: 'MASTER_KEY_DIR is required for file provider',
    };
  }
  const warnings: string[] = [];
  const provider = createFileMasterKeyProvider({
    dir: opts.masterKeyDir,
    onWarning: (m) => warnings.push(m),
  });
  try {
    const bytes = await provider.getKeyBytes(opts.version);
    if (bytes.length < 32) {
      return {
        name: 'master-key',
        state: 'red',
        detail: `expected ≥32 bytes, got ${bytes.length}`,
      };
    }
    if (warnings.length > 0) {
      return {
        name: 'master-key',
        state: 'yellow',
        detail: warnings.join('; '),
      };
    }
    return {
      name: 'master-key',
      state: 'green',
      detail: `provider=file version=${opts.version} (${bytes.length} bytes)`,
    };
  } catch (err) {
    return { name: 'master-key', state: 'red', detail: (err as Error).message };
  }
}

async function runEnvProbe(opts: MasterKeyProbeOpts): Promise<ProbeItem> {
  // env-provider reads from process.env. To make the probe testable we
  // temporarily merge the supplied `env` over process.env for the duration
  // of the call.
  const supplied = opts.env;
  const savedKeys: Record<string, string | undefined> = {};
  if (supplied) {
    for (const [k, v] of Object.entries(supplied)) {
      savedKeys[k] = process.env[k];
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
  try {
    const provider = createEnvMasterKeyProvider();
    const bytes = await provider.getKeyBytes(opts.version);
    if (bytes.length < 32) {
      return {
        name: 'master-key',
        state: 'red',
        detail: `expected ≥32 bytes, got ${bytes.length}`,
      };
    }
    return {
      name: 'master-key',
      state: 'green',
      detail: `provider=env version=${opts.version} (${bytes.length} bytes)`,
    };
  } catch (err) {
    return { name: 'master-key', state: 'red', detail: (err as Error).message };
  } finally {
    if (supplied) {
      for (const [k, v] of Object.entries(savedKeys)) {
        if (v === undefined) delete process.env[k];
        else process.env[k] = v;
      }
    }
  }
}
