import { describe, expect, it } from 'vitest';
import { extractDoctorState } from '../../scripts/lib/parse-doctor.js';

describe('extractDoctorState', () => {
  it('returns "green" when status is green', () => {
    const json = JSON.stringify({ status: 'green', items: [] });
    expect(extractDoctorState(json)).toBe('green');
  });

  it('returns "yellow" when status is yellow', () => {
    const json = JSON.stringify({ status: 'yellow', items: [] });
    expect(extractDoctorState(json)).toBe('yellow');
  });

  it('returns "red" when status is red', () => {
    const json = JSON.stringify({ status: 'red', items: [] });
    expect(extractDoctorState(json)).toBe('red');
  });

  it('throws on malformed JSON', () => {
    expect(() => extractDoctorState('not-json')).toThrow(/parse/i);
  });

  it('throws on missing status field', () => {
    expect(() => extractDoctorState('{}')).toThrow(/status/i);
  });

  it('throws on unknown status value', () => {
    expect(() => extractDoctorState('{"status":"purple"}')).toThrow(/unknown.*purple/i);
  });

  it('ignores extra fields and reads only status', () => {
    const json = JSON.stringify({
      status: 'yellow',
      version: '0.0.0',
      build_sha: 'abc',
      items: [{ name: 'toss', state: 'yellow', detail: 'no cert' }],
    });
    expect(extractDoctorState(json)).toBe('yellow');
  });
});
