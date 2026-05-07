/**
 * Runtime-portable redact path list shared by all Logger adapters.
 *
 * Lives in `src/core/` so the Workers logger can reference it without
 * pulling pino + node:stream into the Workers bundle (which would happen
 * if it imported from a sibling that has a value `import 'pino'`).
 */
export const REDACT_PATHS: ReadonlyArray<string> = [
  'client_secret',
  'client_secret_hashes',
  'access_token',
  'refresh_token',
  'ait_access_token',
  'ait_refresh_token',
  'mtls_cert',
  'mtls_key',
  'mtls_cert_pem',
  'mtls_key_pem',
  'toss_access_token',
  'toss_refresh_token',
  'api_token',
  'master_key',
  'password',
  'password_hash',
  'id_token',
  'code_verifier',
  'code',
  'token',
  'req.headers.authorization',
  'res.headers.authorization',
  'res.headers["set-cookie"]',
  // Wildcard variants for nested objects.
  '*.client_secret',
  '*.access_token',
  '*.refresh_token',
  '*.ait_access_token',
  '*.ait_refresh_token',
  '*.mtls_cert',
  '*.mtls_key',
  '*.mtls_cert_pem',
  '*.mtls_key_pem',
  '*.toss_access_token',
  '*.toss_refresh_token',
  '*.api_token',
  '*.master_key',
  '*.id_token',
  '*.code_verifier',
  '*.code',
  '*.token',
  '*.password',
  '*.password_hash',
];
