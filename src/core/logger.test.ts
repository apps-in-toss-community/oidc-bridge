/**
 * Interface contract test — runs against both Node (pino) and Workers
 * (JSON-line console.log) logger implementations via describe.each.
 */
import { Writable } from 'node:stream';
import { describe, expect, it } from 'vitest';
import { createLogger } from '../runtime/node-logger.js';
import { createWorkersLogger } from '../runtime/workers-logger.js';
import type { Logger } from './logger.js';

type ImplFactory = () => { logger: Logger; getLines: () => string[] };

const impls: [string, ImplFactory][] = [
  [
    'node-logger (pino)',
    () => {
      const lines: string[] = [];
      const stream = new Writable({
        write(chunk, _enc, cb) {
          lines.push(chunk.toString());
          cb();
        },
      });
      const logger = createLogger({ destination: stream, mode: 'json', level: 'debug' });
      return { logger, getLines: () => lines };
    },
  ],
  [
    'workers-logger',
    () => {
      const lines: string[] = [];
      const con = { log: (s: string) => lines.push(s) };
      const logger = createWorkersLogger({ level: 'debug', console: con });
      return { logger, getLines: () => lines };
    },
  ],
];

describe.each(impls)('%s — Logger interface contract', (_name, factory) => {
  it('redacts client_secret and contains the message', () => {
    const { logger, getLines } = factory();
    logger.info({ client_secret: 'super-secret' }, 'hi');
    const line = getLines().join('');
    expect(line).not.toContain('super-secret');
    expect(line).toContain('[Redacted]');
    expect(line).toContain('hi');
  });

  it('child bindings appear in the emitted line', () => {
    const { logger, getLines } = factory();
    logger.child({ tenant: 't' }).info({}, 'hi');
    const line = getLines().join('');
    expect(line).toContain('t');
    expect(line).toContain('hi');
  });

  it('emits valid JSON', () => {
    const { logger, getLines } = factory();
    logger.info({ x: 1 }, 'json-check');
    const raw = getLines().join('').trim();
    expect(() => JSON.parse(raw)).not.toThrow();
  });

  it('msg field present in parsed JSON', () => {
    const { logger, getLines } = factory();
    logger.info({}, 'contract-msg');
    const parsed = JSON.parse(getLines().join('').trim());
    expect(parsed.msg).toBe('contract-msg');
  });

  it('time field is numeric', () => {
    const { logger, getLines } = factory();
    logger.warn({}, 'timing');
    const parsed = JSON.parse(getLines().join('').trim());
    expect(typeof parsed.time).toBe('number');
  });

  it('string-only call works', () => {
    const { logger, getLines } = factory();
    logger.info('bare string');
    const line = getLines().join('');
    expect(line).toContain('bare string');
  });
});
