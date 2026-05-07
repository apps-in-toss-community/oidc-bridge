export interface MasterKeyProvider {
  /** Returns raw key bytes (≥32) for the given version. Throws if missing. */
  getKeyBytes(version: number): Promise<Uint8Array>;
  /** Returns all known versions, sorted ascending. */
  listVersions(): Promise<number[]>;
}
