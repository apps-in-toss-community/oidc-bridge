import { describe, expect, it } from 'vitest';
import { createReporter } from './output.js';

function fakeStdout(isTTY: boolean): { writes: string[]; stream: NodeJS.WriteStream } {
  const writes: string[] = [];
  const stream = {
    isTTY,
    write: (s: string | Uint8Array) => {
      writes.push(typeof s === 'string' ? s : Buffer.from(s).toString('utf8'));
      return true;
    },
  } as unknown as NodeJS.WriteStream;
  return { writes, stream };
}

describe('createReporter', () => {
  it('emits JSON when stdout is not a TTY', () => {
    const { writes, stream } = fakeStdout(false);
    const r = createReporter({ stdout: stream });
    r.report({ status: 'green', items: [{ name: 'env', state: 'green', detail: 'ok' }] });
    const all = writes.join('');
    expect(all.trim()).toBe(
      JSON.stringify({ status: 'green', items: [{ name: 'env', state: 'green', detail: 'ok' }] }),
    );
  });

  it('emits a human table when stdout is a TTY', () => {
    const { writes, stream } = fakeStdout(true);
    const r = createReporter({ stdout: stream });
    r.report({ status: 'green', items: [{ name: 'env', state: 'green', detail: 'ok' }] });
    const all = writes.join('');
    expect(all).toContain('env');
    expect(all).toContain('green');
    expect(all).toContain('ok');
    expect(() => JSON.parse(all)).toThrow();
  });

  it('--json override forces JSON even on TTY', () => {
    const { writes, stream } = fakeStdout(true);
    const r = createReporter({ stdout: stream, forceJson: true });
    r.report({ status: 'green', items: [] });
    expect(() => JSON.parse(writes.join('').trim())).not.toThrow();
  });

  it('omits ANSI escapes in JSON mode', () => {
    const { writes, stream } = fakeStdout(false);
    const r = createReporter({ stdout: stream });
    r.report({ status: 'red', items: [{ name: 'db', state: 'red', detail: 'broken' }] });
    expect(writes.join('')).not.toContain('\x1b[');
  });
});
