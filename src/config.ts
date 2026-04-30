export interface Config {
  issuer: string;
  signingKeyPem: string;
  masterKey: Buffer;
  adminToken: string;
  tenantStore: { kind: 'fs'; dataDir: string } | { kind: 'gcpsm'; projectId: string };
  tossApiBase: string;
}

function required(name: string): string {
  const v = process.env[name];
  if (!v || v.length === 0) {
    throw new Error(`${name} is required`);
  }
  return v;
}

export function loadConfig(): Config {
  const issuer = required('OIDC_ISSUER');
  const signingKeyPem = required('OIDC_SIGNING_KEY');
  const masterKeyB64 = required('OIDC_MASTER_KEY');
  const masterKey = Buffer.from(masterKeyB64, 'base64');
  if (masterKey.length !== 32) {
    throw new Error(`OIDC_MASTER_KEY must decode to 32 bytes (got ${masterKey.length})`);
  }
  const adminToken = required('ADMIN_TOKEN');
  const storeKind = required('TENANT_STORE');
  let tenantStore: Config['tenantStore'];
  if (storeKind === 'fs') {
    tenantStore = { kind: 'fs', dataDir: required('BRIDGE_DATA_DIR') };
  } else if (storeKind === 'gcpsm') {
    tenantStore = { kind: 'gcpsm', projectId: required('GCP_PROJECT_ID') };
  } else {
    throw new Error(`TENANT_STORE must be 'fs' or 'gcpsm' (got '${storeKind}')`);
  }
  const tossApiBase = process.env.TOSS_API_BASE ?? 'https://apps-in-toss-api.toss.im';
  return { issuer, signingKeyPem, masterKey, adminToken, tenantStore, tossApiBase };
}
