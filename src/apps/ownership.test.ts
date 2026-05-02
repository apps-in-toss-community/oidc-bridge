import { describe, expect, it } from 'vitest';
import { computeInitialOwnership, computeOwnershipAfterGrace } from './ownership.js';

describe('computeInitialOwnership', () => {
  const now = new Date('2026-05-01T00:00:00Z');

  it('auto-verifies in alpha stage', () => {
    expect(computeInitialOwnership({ stage: 'alpha', now })).toEqual({
      ownershipStatus: 'verified',
      ownershipGraceUntil: null,
    });
  });

  it('puts apps into pending with 72h grace outside alpha', () => {
    const out = computeInitialOwnership({ stage: 'beta', now });
    expect(out.ownershipStatus).toBe('pending');
    expect(out.ownershipGraceUntil?.toISOString()).toBe('2026-05-04T00:00:00.000Z');
  });

  it('treats undefined stage as non-alpha', () => {
    const out = computeInitialOwnership({ stage: undefined, now });
    expect(out.ownershipStatus).toBe('pending');
  });
});

describe('computeOwnershipAfterGrace', () => {
  const now = new Date('2026-05-05T00:00:00Z');

  it('returns lapsed when grace has expired and status is pending', () => {
    const out = computeOwnershipAfterGrace({
      ownershipStatus: 'pending',
      ownershipGraceUntil: new Date('2026-05-04T00:00:00Z'),
      now,
    });
    expect(out).toEqual({ ownershipStatus: 'lapsed', ownershipGraceUntil: null });
  });

  it('keeps current state when grace has not expired', () => {
    const out = computeOwnershipAfterGrace({
      ownershipStatus: 'pending',
      ownershipGraceUntil: new Date('2026-05-06T00:00:00Z'),
      now,
    });
    expect(out).toBeNull();
  });

  it('keeps current state when status is verified', () => {
    const out = computeOwnershipAfterGrace({
      ownershipStatus: 'verified',
      ownershipGraceUntil: null,
      now,
    });
    expect(out).toBeNull();
  });

  it('keeps current state when status is already lapsed', () => {
    const out = computeOwnershipAfterGrace({
      ownershipStatus: 'lapsed',
      ownershipGraceUntil: null,
      now,
    });
    expect(out).toBeNull();
  });
});
