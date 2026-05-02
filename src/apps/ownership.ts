import type { AppOwnershipStatus } from '../storage/types.js';

export type Stage = 'alpha' | 'beta' | 'ga' | undefined;
const GRACE_MS = 72 * 60 * 60 * 1000;

export interface InitialOwnershipInput {
  stage: Stage;
  now: Date;
}

export interface InitialOwnership {
  ownershipStatus: AppOwnershipStatus;
  ownershipGraceUntil: Date | null;
}

export function computeInitialOwnership(input: InitialOwnershipInput): InitialOwnership {
  if (input.stage === 'alpha') {
    return { ownershipStatus: 'verified', ownershipGraceUntil: null };
  }
  return {
    ownershipStatus: 'pending',
    ownershipGraceUntil: new Date(input.now.getTime() + GRACE_MS),
  };
}

export interface OwnershipAfterGraceInput {
  ownershipStatus: AppOwnershipStatus;
  ownershipGraceUntil: Date | null;
  now: Date;
}

export function computeOwnershipAfterGrace(
  input: OwnershipAfterGraceInput,
): InitialOwnership | null {
  if (input.ownershipStatus !== 'pending') return null;
  if (!input.ownershipGraceUntil) return null;
  if (input.ownershipGraceUntil.getTime() > input.now.getTime()) return null;
  return { ownershipStatus: 'lapsed', ownershipGraceUntil: null };
}
