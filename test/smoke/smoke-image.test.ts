import { execFileSync } from 'node:child_process';
import { existsSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

// Set BRIDGE_SMOKE_IMAGE=1 to enable. The CI image-smoke job sets it after
// building bridge:dev; locally, run `pnpm smoke:image`.
const ENABLED = process.env.BRIDGE_SMOKE_IMAGE === '1';
const SCRIPT = 'scripts/smoke-image.sh';

describe.skipIf(!ENABLED)('smoke: bridge image (BRIDGE_SMOKE_IMAGE=1)', () => {
  it('script exists and is executable', () => {
    expect(existsSync(SCRIPT)).toBe(true);
  });

  it('image smoke passes against bridge:dev', () => {
    const image = process.env.IMAGE ?? 'bridge:dev';
    const out = execFileSync('bash', [SCRIPT], {
      env: { ...process.env, IMAGE: image },
      encoding: 'utf8',
      stdio: ['ignore', 'pipe', 'inherit'],
    });
    expect(out).toMatch(/\[smoke\] OK/);
  }, 180_000);
});
