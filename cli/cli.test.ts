import { spawnSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

describe('cli --help', () => {
  // dist/cli.mjs is produced by `pnpm build`. The test is skipped when the build
  // artefact is absent so `pnpm test` works in environments that haven't built yet.
  // Locally: `pnpm build && pnpm test` to exercise this test.
  // CI runs build before test in the same job, so the skip never fires there.
  it.skipIf(!existsSync('dist/cli.mjs'))('exits 0 and lists tenant commands', () => {
    const r = spawnSync('node', ['dist/cli.mjs', '--help'], { encoding: 'utf8' });
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('tenant');
  });
});
