import { describe, expect, it } from 'vitest';
import { exitCodeFor, runDoctor } from './doctor.js';

describe('runDoctor', () => {
  it('aggregates probes and returns yellow when any item is yellow', async () => {
    const report = await runDoctor({
      probes: [
        async () => ({ name: 'a', state: 'green', detail: 'ok' }),
        async () => ({ name: 'b', state: 'yellow', detail: 'warn' }),
        async () => ({ name: 'c', state: 'green', detail: 'ok' }),
      ],
    });
    expect(report.status).toBe('yellow');
    expect(report.items.map((i) => i.name)).toEqual(['a', 'b', 'c']);
  });

  it('worst state is red when any probe is red', async () => {
    const report = await runDoctor({
      probes: [
        async () => ({ name: 'a', state: 'green', detail: 'ok' }),
        async () => ({ name: 'b', state: 'red', detail: 'broken' }),
      ],
    });
    expect(report.status).toBe('red');
  });

  it('green when every probe is green', async () => {
    const report = await runDoctor({
      probes: [async () => ({ name: 'a', state: 'green', detail: 'ok' })],
    });
    expect(report.status).toBe('green');
  });

  it('captures probe throws as red items (no orchestrator crash)', async () => {
    const report = await runDoctor({
      probes: [
        async () => {
          throw new Error('boom');
        },
        async () => ({ name: 'b', state: 'green', detail: 'ok' }),
      ],
    });
    expect(report.status).toBe('red');
    expect(report.items[0]).toMatchObject({ state: 'red', detail: 'boom' });
  });
});

describe('exitCodeFor', () => {
  it('0 for green', () => {
    expect(exitCodeFor({ status: 'green', items: [] })).toBe(0);
  });
  it('0 for yellow (warning, not failure)', () => {
    expect(exitCodeFor({ status: 'yellow', items: [] })).toBe(0);
  });
  it('1 for red', () => {
    expect(exitCodeFor({ status: 'red', items: [] })).toBe(1);
  });
});
