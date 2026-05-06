import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { maybeStartOtel } from './otel.js';

describe('maybeStartOtel', () => {
  const orig = process.env.OTEL_ENABLED;
  beforeEach(() => {
    delete process.env.OTEL_ENABLED;
  });
  afterEach(() => {
    if (orig === undefined) delete process.env.OTEL_ENABLED;
    else process.env.OTEL_ENABLED = orig;
  });

  it('returns disabled status without importing OTel when env off', async () => {
    const r = await maybeStartOtel();
    expect(r).toEqual({ kind: 'disabled' });
  });

  it('any value other than "1" stays disabled', async () => {
    process.env.OTEL_ENABLED = 'true';
    expect(await maybeStartOtel()).toEqual({ kind: 'disabled' });
    process.env.OTEL_ENABLED = '0';
    expect(await maybeStartOtel()).toEqual({ kind: 'disabled' });
  });

  it('attempts dynamic import when env is on (acceptable to fail in tests)', async () => {
    process.env.OTEL_ENABLED = '1';
    const r = await maybeStartOtel();
    // In a test environment without the optional deps installed, expect kind=missing.
    expect(['started', 'missing']).toContain(r.kind);
  });
});
