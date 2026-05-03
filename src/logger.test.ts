import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { createLogger } from './logger.js';

function captureLogs(): { stream: Writable; lines: string[] } {
  const lines: string[] = [];
  const stream = new Writable({
    write(chunk, _enc, cb) {
      lines.push(chunk.toString());
      cb();
    },
  });
  return { stream, lines };
}

describe('createLogger', () => {
  it('redacts known secret-named fields', () => {
    const { stream, lines } = captureLogs();
    const log = createLogger({ destination: stream, mode: 'json' });

    log.info(
      {
        client_secret: 'super-secret',
        client_secret_hashes: ['hash1'],
        access_token: 'at_xxx',
        refresh_token: 'rt_xxx',
        ait_access_token: 'ait_xxx',
        ait_refresh_token: 'ait_xxx',
        mtls_cert: '-----BEGIN CERTIFICATE-----',
        mtls_key: '-----BEGIN PRIVATE KEY-----',
        api_token: 'tok_xxx',
        master_key: 'deadbeef',
        password: 'p',
      },
      'log with secrets',
    );

    const line = lines.join('');
    expect(line).not.toContain('super-secret');
    expect(line).not.toContain('hash1');
    expect(line).not.toContain('at_xxx');
    expect(line).not.toContain('rt_xxx');
    expect(line).not.toContain('ait_xxx');
    expect(line).not.toContain('-----BEGIN');
    expect(line).not.toContain('tok_xxx');
    expect(line).not.toContain('deadbeef');
    // Pino's default redacted marker is "[Redacted]".
    expect(line).toContain('[Redacted]');
  });

  it('redacts id_token, code_verifier, and code', () => {
    const { stream, lines } = captureLogs();
    const log = createLogger({ destination: stream, mode: 'json' });

    log.info(
      {
        id_token: 'header.payload.signature',
        code_verifier: 'long-random-string',
        code: 'auth-code-from-toss',
      },
      'log with oidc secrets',
    );

    const line = lines.join('');
    expect(line).not.toContain('header.payload.signature');
    expect(line).not.toContain('long-random-string');
    expect(line).not.toContain('auth-code-from-toss');
    expect(line).toContain('[Redacted]');
  });

  it('redacts authorization headers on req/res', () => {
    const { stream, lines } = captureLogs();
    const log = createLogger({ destination: stream, mode: 'json' });

    log.info(
      {
        req: {
          method: 'POST',
          url: '/oidc/token',
          headers: {
            authorization: 'Bearer ait_secret',
            'content-type': 'application/json',
          },
        },
        res: {
          headers: { authorization: 'Bearer ait_secret' },
        },
      },
      'request with auth header',
    );

    const line = lines.join('');
    expect(line).not.toContain('ait_secret');
    expect(line).toContain('[Redacted]');
  });

  it('redacts top-level token form field', () => {
    const { stream, lines } = captureLogs();
    const log = createLogger({ destination: stream, mode: 'json' });

    log.info({ token: 'ait_secret', token_type_hint: 'access_token' }, 'revoke body');

    const line = lines.join('');
    expect(line).not.toContain('ait_secret');
    expect(line).toContain('[Redacted]');
  });

  it('redacts in-memory mTLS PEMs and toss tokens', () => {
    const { stream, lines } = captureLogs();
    const log = createLogger({ destination: stream, mode: 'json' });

    log.info(
      {
        mtls_cert_pem: '-----BEGIN CERTIFICATE-----\nXXX\n-----END CERTIFICATE-----\n',
        mtls_key_pem: '-----BEGIN PRIVATE KEY-----\nYYY\n-----END PRIVATE KEY-----\n',
        toss_access_token: 'AT_PLAINTEXT',
        toss_refresh_token: 'RT_PLAINTEXT',
      },
      'leak-check',
    );

    const line = lines.join('');
    expect(line).not.toContain('XXX');
    expect(line).not.toContain('YYY');
    expect(line).not.toContain('AT_PLAINTEXT');
    expect(line).not.toContain('RT_PLAINTEXT');
    expect(line).toContain('[Redacted]');
  });

  it('redacts password_hash and Set-Cookie headers', () => {
    const { stream, lines } = captureLogs();
    const log = createLogger({ destination: stream, mode: 'json' });

    log.info(
      {
        password_hash: '$2a$12$REAL_HASH_VALUE',
        res: {
          headers: {
            'set-cookie': '__Host-bridge_session=SECRET_SID_VALUE; Path=/; HttpOnly',
          },
        },
      },
      'session-set log',
    );

    const line = lines.join('');
    expect(line).not.toContain('REAL_HASH_VALUE');
    expect(line).not.toContain('SECRET_SID_VALUE');
    expect(line).toContain('[Redacted]');
  });

  it('emits valid JSON in json mode', () => {
    const { stream, lines } = captureLogs();
    const log = createLogger({ destination: stream, mode: 'json' });
    log.info({ foo: 'bar' }, 'hello');
    const parsed = JSON.parse(lines[0]!);
    expect(parsed.msg).toBe('hello');
    expect(parsed.foo).toBe('bar');
    expect(parsed.level).toBe(30);
  });
});
