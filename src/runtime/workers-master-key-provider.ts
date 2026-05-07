import { fromHex } from '../core/bytes.js';
import type { MasterKeyProvider } from '../master-keys/provider.js';

export interface WorkersMasterKeyProviderOptions {
  /** Workers env binding object. Keys like MASTER_KEY_V1_HEX are read from here. */
  env: Record<string, unknown>;
  /** Key prefix. Default: 'MASTER_KEY_V'. Pattern: `${prefix}<n>_HEX`. */
  prefix?: string;
}

const HEX_RE = /^[0-9a-fA-F]+$/;

export function createWorkersMasterKeyProvider(
  opts: WorkersMasterKeyProviderOptions,
): MasterKeyProvider {
  const prefix = opts.prefix ?? 'MASTER_KEY_V';
  const versionRe = new RegExp(`^${escapeRegExp(prefix)}(\\d+)_HEX$`);

  function readHex(version: number): string | undefined {
    const v = opts.env[`${prefix}${version}_HEX`];
    return typeof v === 'string' ? v : undefined;
  }

  return {
    async getKeyBytes(version: number): Promise<Uint8Array> {
      const hex = readHex(version);
      if (!hex) {
        throw new Error(`MasterKeyProvider(workers): version ${version} not present`);
      }
      if (!HEX_RE.test(hex)) {
        throw new Error(`MasterKeyProvider(workers): version ${version} is not valid hex`);
      }
      const bytes = fromHex(hex);
      if (bytes.length < 32) {
        throw new Error(
          `MasterKeyProvider(workers): version ${version} must be at least 32 bytes (got ${bytes.length})`,
        );
      }
      return bytes;
    },

    async listVersions(): Promise<number[]> {
      const versions = new Set<number>();
      for (const k of Object.keys(opts.env)) {
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
