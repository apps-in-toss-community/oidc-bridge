/**
 * MtlsClient port — runtime-agnostic interface.
 *
 * Production code in src/ depends only on this interface. Concrete
 * implementations live in src/runtime/node-mtls.ts (undici-backed) and
 * future src/runtime/workers-mtls.ts (Workers mtls_certificate binding).
 */

export interface MtlsMaterial {
  certPem: string;
  keyPem: string;
}

export interface MtlsClient {
  /**
   * Send an mTLS-authenticated HTTP request. The implementation is
   * responsible for presenting the configured client cert.
   *
   * `url` is absolute. `init` follows standard fetch semantics.
   * Returns a standard `Response`.
   *
   * Throws if the network or TLS handshake fails. The caller is responsible
   * for interpreting HTTP status codes.
   */
  request(url: string, init: RequestInit): Promise<Response>;
}

/**
 * Factory that returns a per-app `MtlsClient`. Implementations cache
 * the client (so e.g. undici Pool / Workers binding aren't rebuilt
 * every call).
 */
export interface MtlsClientFactory {
  /** Returns the client for the given app, building+caching on first call. */
  forApp(appId: string): Promise<MtlsClient>;
}
