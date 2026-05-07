import { fromHex } from '../core/bytes.js';
import type { MasterKeyProvider } from './provider.js';

export interface EnvProviderOptions {
  /** Env-var prefix. Default: "MASTER_KEY_". Pattern: `${prefix}<version>_HEX`. */
  prefix?: string;
}

const HEX_RE = /^[0-9a-fA-F]+$/;

export function createEnvMasterKeyProvider(opts: EnvProviderOptions = {}): MasterKeyProvider {
  const prefix = opts.prefix ?? 'MASTER_KEY_';
  const versionRe = new RegExp(`^${escapeRegExp(prefix)}(\\d+)_HEX$`);

  function readHex(version: number): string | undefined {
    return process.env[`${prefix}${version}_HEX`];
  }

  return {
    async getKeyBytes(version: number): Promise<Uint8Array> {
      const hex = readHex(version);
      if (!hex) throw new Error(`MasterKeyProvider(env): version ${version} not present`);
      if (!HEX_RE.test(hex)) {
        throw new Error(`MasterKeyProvider(env): version ${version} is not valid hex`);
      }
      const bytes = fromHex(hex);
      if (bytes.length < 32) {
        throw new Error(
          `MasterKeyProvider(env): version ${version} must be at least 32 bytes (got ${bytes.length})`,
        );
      }
      return bytes;
    },
    async listVersions(): Promise<number[]> {
      const versions = new Set<number>();
      for (const k of Object.keys(process.env)) {
        const m = versionRe.exec(k);
        if (m?.[1]) versions.add(Number(m[1]));
      }
      return [...versions].sort((a, b) => a - b);
    },
  };
}

function escapeRegExp(str: string): string {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
