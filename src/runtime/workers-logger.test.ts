import { describe, expect, it } from 'vitest';
import { createWorkersLogger } from './workers-logger.js';

function captureLines(): { lines: string[]; con: { log: (s: string) => void } } {
  const lines: string[] = [];
  return { lines, con: { log: (s: string) => lines.push(s) } };
}

describe('createWorkersLogger', () => {
  it('redacts top-level client_secret', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ console: con });
    log.info({ client_secret: 'x' }, 'test');
    expect(lines).toHaveLength(1);
    expect(lines[0]).not.toContain('x');
    expect(lines[0]).toContain('[Redacted]');
  });

  it('redacts nested client_secret', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ console: con });
    log.info({ outer: { client_secret: 'y' } }, 'nested');
    expect(lines[0]).not.toContain('y');
    expect(lines[0]).toContain('[Redacted]');
  });

  it('handles string-only call', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ console: con });
    log.info('hello');
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]!);
    expect(parsed.msg).toBe('hello');
  });

  it('handles obj + message call', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ console: con });
    log.info({ user: 'u' }, 'hello');
    const parsed = JSON.parse(lines[0]!);
    expect(parsed.user).toBe('u');
    expect(parsed.msg).toBe('hello');
  });

  it('child bindings are included in emitted line', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ console: con });
    log.child({ tenant: 't1' }).info({}, 'msg');
    const parsed = JSON.parse(lines[0]!);
    expect(parsed.tenant).toBe('t1');
  });

  it('level filtering: info suppressed when minLevel=warn', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ level: 'warn', console: con });
    log.info({}, 'suppressed');
    expect(lines).toHaveLength(0);
    log.error({}, 'emitted');
    expect(lines).toHaveLength(1);
  });

  it('emits parseable JSON', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ console: con });
    log.warn({ foo: 'bar' }, 'check');
    expect(() => JSON.parse(lines[0]!)).not.toThrow();
  });

  it('includes numeric level field matching pino convention', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ console: con });
    log.info({}, 'x');
    const parsed = JSON.parse(lines[0]!);
    expect(parsed.level).toBe(30); // pino info == 30
  });

  it('includes time field', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ console: con });
    log.info({}, 'x');
    const parsed = JSON.parse(lines[0]!);
    expect(typeof parsed.time).toBe('number');
  });

  it('redacts all known secret fields', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ console: con });
    log.info(
      {
        access_token: 'at',
        refresh_token: 'rt',
        ait_access_token: 'aitat',
        ait_refresh_token: 'aitrt',
        mtls_cert: 'cert',
        mtls_key: 'key',
        api_token: 'tok',
        master_key: 'mk',
        password: 'pw',
        password_hash: 'ph',
        id_token: 'idt',
        code_verifier: 'cv',
        token: 'tkn',
      },
      'secrets',
    );
    const line = lines[0]!;
    for (const secret of [
      'at',
      'rt',
      'aitat',
      'aitrt',
      'cert',
      'key',
      'tok',
      'mk',
      'pw',
      'ph',
      'idt',
      'cv',
      'tkn',
    ]) {
      expect(line).not.toContain(`"${secret}"`);
    }
    expect(line).toContain('[Redacted]');
  });

  it('child inherits parent level', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ level: 'error', console: con });
    const child = log.child({ svc: 'x' });
    child.warn({}, 'should not appear');
    expect(lines).toHaveLength(0);
    child.fatal({}, 'should appear');
    expect(lines).toHaveLength(1);
  });

  it('debug level emits debug messages', () => {
    const { lines, con } = captureLines();
    const log = createWorkersLogger({ level: 'debug', console: con });
    log.debug({}, 'verbose');
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]!);
    expect(parsed.level).toBe(20);
  });
});
