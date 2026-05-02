import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { MasterKeyProvider } from './provider.js';

export interface FileProviderOptions {
  dir: string;
  onWarning?: (msg: string) => void;
}

const FILE_RE = /^v(\d+)\.key$/;

export function createFileMasterKeyProvider(opts: FileProviderOptions): MasterKeyProvider {
  const dir = opts.dir;
  const warn = opts.onWarning ?? ((m: string) => console.warn(m));

  function pathFor(version: number): string {
    return join(dir, `v${version}.key`);
  }

  return {
    async getKeyBytes(version: number): Promise<Buffer> {
      const path = pathFor(version);
      let stat: ReturnType<typeof statSync>;
      try {
        stat = statSync(path);
      } catch {
        throw new Error(`MasterKeyProvider(file): version ${version} not present at ${path}`);
      }
      // POSIX-only check; on Windows the mode bits are not meaningful for "world".
      if (process.platform !== 'win32' && (stat.mode & 0o077) !== 0) {
        warn(
          `MasterKeyProvider(file): ${path} permissions are too open (${(stat.mode & 0o777).toString(8)}); chmod 600 recommended`,
        );
      }
      const bytes = readFileSync(path);
      if (bytes.length < 32) {
        throw new Error(
          `MasterKeyProvider(file): ${path} must be at least 32 bytes (got ${bytes.length})`,
        );
      }
      return bytes;
    },
    async listVersions(): Promise<number[]> {
      let entries: string[];
      try {
        entries = readdirSync(dir);
      } catch {
        return [];
      }
      const out: number[] = [];
      for (const e of entries) {
        const m = FILE_RE.exec(e);
        if (m?.[1]) out.push(Number(m[1]));
      }
      return out.sort((a, b) => a - b);
    },
  };
}
