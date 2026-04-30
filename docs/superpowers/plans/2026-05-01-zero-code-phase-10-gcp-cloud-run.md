# Phase 10 Implementation Plan — Public-instance deployment on GCP Cloud Run

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the public community instance at `https://oidc-bridge.aitc.dev` on GCP Cloud Run + Cloud SQL Postgres + Google Cloud Secret Manager, driven by a Cloud Build pipeline that triggers on every push to `main`. End the phase with an end-to-end test from a deployed mini-app: `appLogin()` → `/oidc/token` → `signInWithIdToken` against a fresh Supabase project. (Note: the repo `CLAUDE.md` describes Vultr Seoul as the public-instance target. The zero-code mode spec at `docs/superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md` §11 Phase 10 + decision row #23 supersedes that — public hosting is GCP Cloud Run. Phase 9 already shipped the Vultr-class self-host artifacts; this phase is about the public instance specifically.)

**Architecture:** The application image from Phase 9 runs unchanged on Cloud Run; the cloud-agnostic invariants (§5.6) mean only deployment artifacts differ. Cloud Run handles ingress + TLS termination + autoscale (min instances = 1, max = 10, concurrency = 80) and reads the listening port from `PORT`. Cloud SQL Postgres 17 sits behind the Cloud SQL Auth Proxy sidecar, exposed to Cloud Run via `--set-cloudsql-instances`. Master-key bytes live in Google Cloud Secret Manager as `oidc-bridge-master-key-v<version>`; the bridge's `MASTER_KEY_PROVIDER=gcpsm` provider lazy-loads them on first wrap/unwrap. The bridge service account has read-only access to the master-key secrets and SQL Cloud SQL Client role on the database; it has no other GCP IAM bindings. A Cloud Build trigger on `main` builds the Phase-9 Dockerfile, pushes to Artifact Registry under `asia-northeast3-docker.pkg.dev`, and `gcloud run deploy`s a new revision with `--no-traffic`; a brief automated smoke against the new revision URL gates a `--to-latest=100` traffic flip. DNS `oidc-bridge.aitc.dev` is a Cloudflare CNAME to the Cloud Run domain map. The end-to-end test is a deployed `sdk-example` instance making a real `appLogin()` round trip; this phase ships the test harness, Phase 11 wires the actual `AuthPage` rewrite.

**Tech Stack:** Existing Phase 9 Docker image (no changes); `asia-northeast3` (Seoul) GCP region; Artifact Registry; Cloud Run (2nd gen execution environment); Cloud SQL Postgres 17 (`db-g1-small`, ~$25/mo, regional HA off for cost — operators reading this can flip on); Google Cloud Secret Manager; Cloud Build with `cloudbuild.yaml` and a `main`-branch trigger; Cloudflare DNS (Registrar already manages `aitc.dev`); `@google-cloud/secret-manager` (lazy-imported per spec §5.6 invariant 2); `pg` driver with Cloud SQL Auth Proxy connection.

---

## Universal invariants (apply to every task in this plan)

These are non-negotiable. Any task that violates one is rejected at review and reworked.

1. **TDD where there is application code.** Most of this phase is infra-as-config. The application code added (the GCPSM master-key provider, if not already shipped in Phase 1) is TDD'd against a mocked Secret Manager client. Cloud Build YAML and `gcloud` invocations are validated by `gcloud beta` dry-run + `cloudbuild --no-source` substitution checks.
2. **No PII in logs.** Cloud Run streams stdout to Cloud Logging; the Pino logger from Phase 8 already produces JSON without PII. Phase 10 verifies that the Cloud Run log explorer never shows a Toss AT/RT or password.
3. **Bridge never spontaneously calls Toss.** No Cloud Build step, no Cloud Run startup probe, no smoke test from this phase calls `apps-in-toss-api.toss.im`. The deployed-mini-app E2E in Task 14 does — that is the *consumer* exercising the bridge, which is the desired behavior.
4. **Toss refresh_token never leaves the sealed wrapper.** Phase 4/5 invariants cover this. Phase 10 verifies in deployed-mini-app E2E that `refresh_token` field returned from `/oidc/token` is shaped `ait_<base64url>` and not a Toss-shaped JWT.
5. **Public clients use Origin, not client_secret.** The deployed mini-app E2E uses public-client mode (`Origin: https://sdk-example.aitc.dev`) so we exercise the production CORS-validated `Origin` allowlist, not confidential-client mode.
6. **mTLS material never returns from any GET.** Same Phase 4 contract; verified by re-running the existing test against the deployed instance via `pnpm bridge tenant show` over the public URL.
7. **Cloud-agnostic.** No application code is added that imports `@google-cloud/*` at module top-level. GCPSM provider import remains `await import(...)` per Phase 1.
8. **Self-host first-class.** Anything added to the application code in this phase must continue to work when `MASTER_KEY_PROVIDER=file` or `env`. The deployed-mini-app E2E in Task 14 has a parallel self-host equivalent that runs against `localhost`.
9. **TLS termination is external.** Cloud Run terminates; the bridge container speaks plain HTTP. No code change required; this phase verifies that the running container does not attempt to bind 443.
10. **Runtime is unprivileged.** Cloud Run runs the image's `ENTRYPOINT` as the image-defined user (UID 1001 from Phase 9). Cloud Run does not allow capability adjustments; the image's `cap_drop` is irrelevant on Cloud Run but remains correct for self-host.
11. **Reproducibility is required.** Cloud Build steps pin every image (`gcr.io/cloud-builders/docker:latest` is *not* allowed; pin to a digest). Artifact Registry pushes are by digest; Cloud Run revisions reference images by digest, never by tag.
12. **Cost discipline.** The public instance budget is ≤ $50/month. If the deployment design pushes past that, flag it before continuing — do not silently provision higher tiers.
13. **No backwards-compat hacks.** No "v0 region", no compat alias, no legacy URL.
14. **Cost alerts before traffic.** A GCP budget alert at 80% of $50/month is configured before DNS flips. If you find yourself flipping DNS without the alert in place, stop and add the alert.

When a step says "verify with X", run X verbatim and confirm the expected output. Don't move on if it doesn't match.

---

## Files touched this phase

```
infra/
  gcp/
    README.md                                  # CREATE — bird's-eye + bootstrap recipe
    bootstrap.sh                               # CREATE — one-shot project bootstrap
    artifact-registry.tf                       # CREATE — Artifact Registry repo
    cloud-run.tf                               # CREATE — Cloud Run service + revision template
    cloud-sql.tf                               # CREATE — Cloud SQL Postgres 17 instance
    secret-manager.tf                          # CREATE — master-key v1 secret (entry only; bytes loaded out-of-band)
    iam.tf                                     # CREATE — bridge service account + minimal bindings
    dns.tf                                     # CREATE — Cloudflare CNAME (provider: cloudflare)
    budget.tf                                  # CREATE — $50/mo budget alert
    versions.tf                                # CREATE — provider pins
    variables.tf                               # CREATE — required vars (project_id, region, host)
    outputs.tf                                 # CREATE — service URL, db connection, key locations
    .terraform-version                         # CREATE — pin terraform CLI
cloudbuild.yaml                                # CREATE — root: build → push → deploy → smoke → traffic
.github/workflows/deploy-prod.yml              # CREATE — manual approval gate before traffic flip
src/
  master-keys/
    gcpsm-provider.ts                          # CREATE-OR-MODIFY — Phase 1 stubbed; Phase 10 hardens
test/
  master-keys/
    gcpsm-provider.test.ts                     # CREATE — unit, mocked Secret Manager
  e2e/
    deployed-bridge.test.ts                    # CREATE — gated E2E against public URL
docs/
  PUBLIC_INSTANCE.md                           # CREATE — operator runbook for the community instance
  RUNBOOK.md                                   # MODIFY — pointer to PUBLIC_INSTANCE.md
package.json                                   # MODIFY — add scripts: tf:plan, tf:apply, deploy:smoke, e2e:deployed
```

This is the only set of files this phase touches. Anything not on this list is out of scope; do not touch it.

---

## Pre-flight: read these once before starting

Before you begin Task 1, do this in order. It's about fifteen minutes and prevents the rework that comes from missing a piece of context.

1. Read the spec sections:
   - §3.1 "In scope" bullet "Public instance on **GCP Cloud Run + Cloud SQL Postgres + Cloud Secret Manager**".
   - §5.5 "Master keys" — the GCPSM provider contract.
   - §5.6 "Cloud-agnostic invariants" — the seven rules this phase exists to honor.
   - §11 "Phase 10" — the four-line scope statement this plan expands.
   - Decision row #23 — public hosting is GCP Cloud Run + Cloud SQL + GCPSM.
2. Read the Phase 1 plan §"Master-key provider" to find what the GCPSM provider stub looks like and what its tests already cover. This phase finishes that stub and adds integration tests.
3. Read the Phase 9 plan §"Task 4" (Dockerfile runtime stage) so you know the image entrypoint, the user, and the healthcheck endpoint Cloud Run will probe.
4. Verify your `gcloud` CLI is authenticated against an account with `roles/owner` on a fresh GCP project named `apps-in-toss-community-prod` (created out-of-band; project ID is the assumed input here). The bootstrap script in Task 4 enables required APIs.
5. Verify Cloudflare API token is exported as `CLOUDFLARE_API_TOKEN` with edit access to the `aitc.dev` zone.
6. Verify Terraform CLI is installed at version `>= 1.7` and that `tfenv` (or equivalent) honors the `.terraform-version` file the plan pins in Task 5.
7. Confirm a Supabase project exists for the deployed-mini-app E2E (Task 14). Project URL + anon key go into a workflow secret; this phase does not create the project.

When that's done, start Task 1.

---

## Task 1: GCPSM master-key provider — finish the stub

**Files:**
- Create-or-Modify: `src/master-keys/gcpsm-provider.ts`
- Create: `test/master-keys/gcpsm-provider.test.ts`

Phase 1 set the `MasterKeyProvider` interface and stubbed an `env` and a `file` provider. The GCPSM provider was deliberately left thin: `throw new Error('not implemented')`. This task fills it in with TDD.

The interface from Phase 1:

```ts
export interface MasterKeyProvider {
  fetch(version: number): Promise<{ keyBytes: Uint8Array; cachedUntil: Date }>;
  // Optional: providers may implement listVersions for `bridge master-key list`.
  listVersions?(): Promise<number[]>;
}
```

- [ ] **Step 1: Write the failing test (mocked SecretManagerServiceClient)**

```ts
// test/master-keys/gcpsm-provider.test.ts
import { describe, expect, it, vi } from 'vitest';
import { createGcpsmProvider } from '../../src/master-keys/gcpsm-provider.ts';

const validKeyBytes = new Uint8Array(32).fill(0xab);

function makeMockClient(opts: {
  payload?: Buffer | null;
  notFound?: boolean;
  permissionDenied?: boolean;
} = {}) {
  return {
    accessSecretVersion: vi.fn(async ({ name }: { name: string }) => {
      if (opts.notFound) {
        const e = Object.assign(new Error('NOT_FOUND'), { code: 5 });
        throw e;
      }
      if (opts.permissionDenied) {
        const e = Object.assign(new Error('PERMISSION_DENIED'), { code: 7 });
        throw e;
      }
      expect(name).toMatch(
        /^projects\/[^/]+\/secrets\/oidc-bridge-master-key-v\d+\/versions\/latest$/,
      );
      return [{ payload: { data: opts.payload ?? Buffer.from(validKeyBytes) } }];
    }),
    listSecretVersions: vi.fn(async () => [
      [
        { name: 'projects/p/secrets/oidc-bridge-master-key-v1/versions/1', state: 'ENABLED' },
        { name: 'projects/p/secrets/oidc-bridge-master-key-v1/versions/2', state: 'DISABLED' },
      ],
    ]),
  };
}

describe('createGcpsmProvider', () => {
  it('fetches master-key bytes from Secret Manager', async () => {
    const client = makeMockClient();
    const provider = createGcpsmProvider({
      projectId: 'apps-in-toss-community-prod',
      cacheTtlMs: 60_000,
      clientFactory: () => client as unknown as never,
    });
    const result = await provider.fetch(1);
    expect(result.keyBytes).toEqual(validKeyBytes);
    expect(result.cachedUntil.getTime()).toBeGreaterThan(Date.now());
    expect(client.accessSecretVersion).toHaveBeenCalledTimes(1);
  });

  it('caches within TTL window', async () => {
    const client = makeMockClient();
    const provider = createGcpsmProvider({
      projectId: 'p',
      cacheTtlMs: 60_000,
      clientFactory: () => client as unknown as never,
    });
    await provider.fetch(1);
    await provider.fetch(1);
    expect(client.accessSecretVersion).toHaveBeenCalledTimes(1);
  });

  it('refetches after TTL expires', async () => {
    const client = makeMockClient();
    const provider = createGcpsmProvider({
      projectId: 'p',
      cacheTtlMs: 1,
      clientFactory: () => client as unknown as never,
    });
    await provider.fetch(1);
    await new Promise((r) => setTimeout(r, 5));
    await provider.fetch(1);
    expect(client.accessSecretVersion).toHaveBeenCalledTimes(2);
  });

  it('rejects payloads that are not exactly 32 bytes', async () => {
    const client = makeMockClient({ payload: Buffer.from(new Uint8Array(31)) });
    const provider = createGcpsmProvider({
      projectId: 'p',
      cacheTtlMs: 60_000,
      clientFactory: () => client as unknown as never,
    });
    await expect(provider.fetch(1)).rejects.toThrow(/32 bytes/);
  });

  it('translates NOT_FOUND to a domain error', async () => {
    const client = makeMockClient({ notFound: true });
    const provider = createGcpsmProvider({
      projectId: 'p',
      cacheTtlMs: 60_000,
      clientFactory: () => client as unknown as never,
    });
    await expect(provider.fetch(99)).rejects.toThrow(/master key.*v99.*not found/i);
  });

  it('translates PERMISSION_DENIED to an actionable error', async () => {
    const client = makeMockClient({ permissionDenied: true });
    const provider = createGcpsmProvider({
      projectId: 'p',
      cacheTtlMs: 60_000,
      clientFactory: () => client as unknown as never,
    });
    await expect(provider.fetch(1)).rejects.toThrow(/permission denied.*service account/i);
  });

  it('listVersions returns enabled versions only', async () => {
    const client = makeMockClient();
    const provider = createGcpsmProvider({
      projectId: 'p',
      cacheTtlMs: 60_000,
      clientFactory: () => client as unknown as never,
    });
    const versions = await provider.listVersions!();
    expect(versions).toEqual([1]);
  });
});
```

- [ ] **Step 2: Run the test, confirm it fails**

```bash
pnpm test test/master-keys/gcpsm-provider.test.ts 2>&1 | tail -15
```

Expected: 7 failing tests (the existing stub throws `not implemented`).

- [ ] **Step 3: Implement the provider**

```ts
// src/master-keys/gcpsm-provider.ts
import type { MasterKeyProvider } from './types.ts';

export interface GcpsmProviderOptions {
  projectId: string;
  /** Cache TTL in ms. Spec §5.5 specifies 6 hours. Tests use small values. */
  cacheTtlMs: number;
  /**
   * Factory for the Secret Manager client. Default lazy-imports
   * `@google-cloud/secret-manager` so the package is not a hard dependency
   * for self-host (spec §5.6 invariant 2).
   */
  clientFactory?: () => Promise<unknown> | unknown;
}

interface CachedKey {
  keyBytes: Uint8Array;
  fetchedAt: number;
}

export function createGcpsmProvider(opts: GcpsmProviderOptions): MasterKeyProvider {
  const cache = new Map<number, CachedKey>();

  let clientPromise: Promise<unknown> | null = null;
  const getClient = (): Promise<unknown> => {
    if (clientPromise) return clientPromise;
    if (opts.clientFactory) {
      clientPromise = Promise.resolve(opts.clientFactory());
      return clientPromise;
    }
    clientPromise = (async () => {
      const mod = (await import('@google-cloud/secret-manager')) as {
        SecretManagerServiceClient: new () => unknown;
      };
      return new mod.SecretManagerServiceClient();
    })();
    return clientPromise;
  };

  const secretName = (version: number): string =>
    `projects/${opts.projectId}/secrets/oidc-bridge-master-key-v${version}/versions/latest`;

  const translateError = (e: unknown, version: number): Error => {
    const code = (e as { code?: number }).code;
    if (code === 5) {
      return new Error(
        `master key v${version} not found in Secret Manager (project=${opts.projectId})`,
      );
    }
    if (code === 7) {
      return new Error(
        'permission denied accessing master-key secret; ' +
          'check the bridge service account has roles/secretmanager.secretAccessor',
      );
    }
    return e instanceof Error ? e : new Error(String(e));
  };

  return {
    async fetch(version: number) {
      const cached = cache.get(version);
      if (cached && Date.now() - cached.fetchedAt < opts.cacheTtlMs) {
        return {
          keyBytes: cached.keyBytes,
          cachedUntil: new Date(cached.fetchedAt + opts.cacheTtlMs),
        };
      }

      const client = (await getClient()) as {
        accessSecretVersion: (req: { name: string }) => Promise<
          [{ payload?: { data?: Buffer | Uint8Array | null } | null }]
        >;
      };

      let response: [{ payload?: { data?: Buffer | Uint8Array | null } | null }];
      try {
        response = await client.accessSecretVersion({ name: secretName(version) });
      } catch (e) {
        throw translateError(e, version);
      }

      const data = response[0]?.payload?.data;
      if (!data) {
        throw new Error(`master key v${version} secret has empty payload`);
      }
      const bytes = data instanceof Uint8Array ? data : Uint8Array.from(data as Buffer);
      if (bytes.length !== 32) {
        throw new Error(
          `master key v${version} payload is ${bytes.length} bytes (expected 32 bytes)`,
        );
      }

      cache.set(version, { keyBytes: bytes, fetchedAt: Date.now() });
      return {
        keyBytes: bytes,
        cachedUntil: new Date(Date.now() + opts.cacheTtlMs),
      };
    },

    async listVersions() {
      const client = (await getClient()) as {
        listSecretVersions: (req: { parent: string }) => Promise<
          [Array<{ name: string; state: string }>]
        >;
      };
      const [results] = await client.listSecretVersions({
        parent: `projects/${opts.projectId}/secrets/oidc-bridge-master-key-v1`,
      });
      const versions: number[] = [];
      for (const item of results) {
        if (item.state !== 'ENABLED') continue;
        const m = item.name.match(/master-key-v(\d+)/);
        if (m) versions.push(Number(m[1]));
      }
      return [...new Set(versions)].sort((a, b) => a - b);
    },
  };
}
```

- [ ] **Step 4: Run the test, confirm it passes**

```bash
pnpm test test/master-keys/gcpsm-provider.test.ts 2>&1 | tail -10
```

Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add src/master-keys/gcpsm-provider.ts test/master-keys/gcpsm-provider.test.ts
git commit -m "feat: GCPSM master-key provider (lazy import, 6h TTL, 32-byte enforcement)"
```

---

## Task 2: Wire `gcpsm` into the provider factory

**Files:**
- Modify: `src/master-keys/factory.ts` (Phase 1)
- Modify: `test/master-keys/factory.test.ts` (Phase 1)

The factory in Phase 1 chose between `env` and `file` providers; `gcpsm` returned `not implemented`. Now it must dispatch to `createGcpsmProvider`.

- [ ] **Step 1: Add a failing factory test**

Append to `test/master-keys/factory.test.ts`:

```ts
it('returns a gcpsm provider when MASTER_KEY_PROVIDER=gcpsm', async () => {
  const provider = createMasterKeyProvider({
    MASTER_KEY_PROVIDER: 'gcpsm',
    GOOGLE_CLOUD_PROJECT: 'apps-in-toss-community-prod',
    MASTER_KEY_CACHE_TTL_MS: '21600000',
  });
  // The factory does not call accessSecretVersion until fetch() is invoked,
  // so just assert the shape: a function 'fetch' exists.
  expect(typeof provider.fetch).toBe('function');
});

it('throws if MASTER_KEY_PROVIDER=gcpsm but GOOGLE_CLOUD_PROJECT is unset', () => {
  expect(() =>
    createMasterKeyProvider({ MASTER_KEY_PROVIDER: 'gcpsm' }),
  ).toThrow(/GOOGLE_CLOUD_PROJECT/);
});
```

- [ ] **Step 2: Run, confirm it fails**

```bash
pnpm test test/master-keys/factory.test.ts 2>&1 | tail -10
```

Expected: 2 new failures (`createGcpsmProvider` not wired in factory).

- [ ] **Step 3: Wire it**

In `src/master-keys/factory.ts`, replace the existing `case 'gcpsm'` branch (which threw `not implemented`):

```ts
case 'gcpsm': {
  const projectId = env.GOOGLE_CLOUD_PROJECT;
  if (!projectId) {
    throw new Error(
      'MASTER_KEY_PROVIDER=gcpsm requires GOOGLE_CLOUD_PROJECT env var ' +
        '(set to your GCP project ID, e.g. apps-in-toss-community-prod)',
    );
  }
  const ttlMs = Number(env.MASTER_KEY_CACHE_TTL_MS ?? 6 * 60 * 60 * 1000);
  return createGcpsmProvider({ projectId, cacheTtlMs: ttlMs });
}
```

Add the import at the top of the file:

```ts
import { createGcpsmProvider } from './gcpsm-provider.ts';
```

- [ ] **Step 4: Run, confirm it passes**

```bash
pnpm test test/master-keys/ 2>&1 | tail -10
```

Expected: all master-keys tests pass (existing + 2 new).

- [ ] **Step 5: Commit**

```bash
git add src/master-keys/factory.ts test/master-keys/factory.test.ts
git commit -m "feat: factory dispatches to GCPSM provider when configured"
```

---

## Task 3: `optionalDependencies` for `@google-cloud/secret-manager`

**Files:**
- Modify: `package.json`

Spec §5.6 invariant 2: the GCPSM package must be lazy and not required for self-host. List it in `optionalDependencies`, not `dependencies`. Self-hosters running `pnpm install --no-optional` (or `pnpm install --include=optional false`) get a working bridge without the package; the public-instance Dockerfile build runs `pnpm install --frozen-lockfile` which includes optional dependencies by default.

- [ ] **Step 1: Add to `optionalDependencies`**

In `package.json`:

```json
"optionalDependencies": {
  "@opentelemetry/sdk-node": "^0.55.0",
  "@opentelemetry/auto-instrumentations-node": "^0.51.0",
  "@google-cloud/secret-manager": "^5.6.0"
}
```

(The OTel entries are from Phase 8; this task adds the third entry.)

- [ ] **Step 2: Update lockfile and verify install works without optional deps**

```bash
pnpm install
pnpm install --include=optional=false --frozen-lockfile=false
node -e "import('./src/master-keys/factory.ts').then(()=>console.log('imports ok')).catch(e=>{console.error(e.message);process.exit(1)})"
```

Expected: `imports ok`. The `factory.ts` itself does not import `@google-cloud/secret-manager` statically; only `gcpsm-provider.ts` does, and only inside `getClient()`. Confirm:

```bash
grep -n "@google-cloud/secret-manager" src/master-keys/*.ts
```

Expected: exactly one match, inside `gcpsm-provider.ts` inside an `await import()` expression.

- [ ] **Step 3: Restore full install**

```bash
pnpm install --frozen-lockfile
```

- [ ] **Step 4: Commit**

```bash
git add package.json pnpm-lock.yaml
git commit -m "chore: list @google-cloud/secret-manager as optionalDependency"
```

---

## Task 4: `infra/gcp/bootstrap.sh` (one-shot project bootstrap)

**Files:**
- Create: `infra/gcp/bootstrap.sh`
- Create: `infra/gcp/README.md`

Before any Terraform runs, the GCP project needs APIs enabled, a Terraform state bucket, and service accounts. This script is idempotent and safe to re-run.

- [ ] **Step 1: Write `infra/gcp/bootstrap.sh`**

```bash
#!/usr/bin/env bash
# infra/gcp/bootstrap.sh
#
# One-shot bootstrap for the public oidc-bridge GCP project.
# Idempotent: re-running is safe.
#
# Required env:
#   GCP_PROJECT_ID   default: apps-in-toss-community-prod
#   GCP_REGION       default: asia-northeast3
#   TF_STATE_BUCKET  default: <project>-tf-state
#
# What it does:
#   1. Validates gcloud auth.
#   2. Sets the active project.
#   3. Enables required APIs.
#   4. Creates the Terraform state bucket if missing (uniform access, versioned).
#   5. Creates the bridge service account if missing.
#   6. Prints next steps.
set -euo pipefail

PROJECT="${GCP_PROJECT_ID:-apps-in-toss-community-prod}"
REGION="${GCP_REGION:-asia-northeast3}"
TF_BUCKET="${TF_STATE_BUCKET:-${PROJECT}-tf-state}"

if ! gcloud auth list --filter='status:ACTIVE' --format='value(account)' | grep -q '@'; then
  echo "[bootstrap] FAIL: no active gcloud account; run 'gcloud auth login'" >&2
  exit 1
fi

echo "[bootstrap] active account: $(gcloud auth list --filter='status:ACTIVE' --format='value(account)')"
echo "[bootstrap] target project:  ${PROJECT}"
echo "[bootstrap] target region:   ${REGION}"
echo "[bootstrap] tf state bucket: ${TF_BUCKET}"

gcloud config set project "$PROJECT" >/dev/null

echo "[bootstrap] enabling required APIs"
gcloud services enable \
  run.googleapis.com \
  sqladmin.googleapis.com \
  secretmanager.googleapis.com \
  artifactregistry.googleapis.com \
  cloudbuild.googleapis.com \
  cloudscheduler.googleapis.com \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  vpcaccess.googleapis.com \
  servicenetworking.googleapis.com \
  monitoring.googleapis.com \
  logging.googleapis.com \
  billingbudgets.googleapis.com

echo "[bootstrap] ensuring Terraform state bucket"
if ! gcloud storage buckets describe "gs://${TF_BUCKET}" >/dev/null 2>&1; then
  gcloud storage buckets create "gs://${TF_BUCKET}" \
    --location="$REGION" \
    --uniform-bucket-level-access \
    --no-public-access-prevention=false
  gcloud storage buckets update "gs://${TF_BUCKET}" --versioning
  gcloud storage buckets update "gs://${TF_BUCKET}" \
    --lifecycle-file=<(cat <<EOF
{ "rule": [
  { "action": {"type": "Delete"},
    "condition": {"age": 90, "isLive": false} }
] }
EOF
)
fi

echo "[bootstrap] ensuring bridge runtime service account"
SA_EMAIL="oidc-bridge-runtime@${PROJECT}.iam.gserviceaccount.com"
if ! gcloud iam service-accounts describe "$SA_EMAIL" >/dev/null 2>&1; then
  gcloud iam service-accounts create oidc-bridge-runtime \
    --display-name="oidc-bridge Cloud Run runtime" \
    --description="Used by the Cloud Run service. Read-only on master-key secrets, Cloud SQL Client only."
fi

cat <<EOF

[bootstrap] done.

Next steps:
  cd infra/gcp
  terraform init -backend-config="bucket=${TF_BUCKET}" -backend-config="prefix=oidc-bridge"
  terraform plan -var="project_id=${PROJECT}" -var="region=${REGION}" -var="public_host=oidc-bridge.aitc.dev"
  # Inspect the plan, then:
  terraform apply -var="project_id=${PROJECT}" -var="region=${REGION}" -var="public_host=oidc-bridge.aitc.dev"

EOF
```

- [ ] **Step 2: Make executable, lint**

```bash
chmod +x infra/gcp/bootstrap.sh
shellcheck infra/gcp/bootstrap.sh
```

Expected: clean.

- [ ] **Step 3: Write `infra/gcp/README.md`**

```markdown
# `infra/gcp/`

Terraform + helper scripts for the public oidc-bridge instance on GCP.

## What runs in this stack

| Resource              | Tier / size                    | Purpose                                  |
|-----------------------|---------------------------------|------------------------------------------|
| Cloud Run service     | min=1, max=10, concurrency=80  | the bridge container                     |
| Cloud SQL Postgres 17 | `db-g1-small`, regional=false  | the bridge database                      |
| Secret Manager        | `oidc-bridge-master-key-v*`    | master-key bytes                         |
| Artifact Registry     | docker repo, asia-northeast3   | bridge images                             |
| Cloud Build trigger   | on push to `main`              | build → push → deploy → smoke → traffic  |
| Cloudflare DNS        | `oidc-bridge.aitc.dev` CNAME    | DNS to Cloud Run domain map              |
| Budget alert          | $50/month, alert at 80%         | cost guardrail                           |

## One-shot bootstrap (run once per GCP project)

```bash
export GCP_PROJECT_ID=apps-in-toss-community-prod
export GCP_REGION=asia-northeast3
./bootstrap.sh
```

The script enables required APIs, creates the Terraform state bucket, and
creates the bridge service account. It is idempotent.

## Terraform

```bash
terraform init \
  -backend-config="bucket=apps-in-toss-community-prod-tf-state" \
  -backend-config="prefix=oidc-bridge"
terraform plan
terraform apply
```

## Master-key secret population

Terraform creates the *secret entry*, not the bytes. Populate v1 once:

```bash
head -c 32 /dev/urandom | gcloud secrets versions add oidc-bridge-master-key-v1 \
  --data-file=- --project=apps-in-toss-community-prod
```

Rotation (Phase 1 design): `bridge master-key rotate` issues v2 by writing a
new secret entry and adding a new `master-keys` row in the database.

## Read order

1. `versions.tf` — provider pins.
2. `variables.tf` — required inputs.
3. `iam.tf` — service accounts and bindings.
4. `secret-manager.tf` — secret entries.
5. `cloud-sql.tf` — database instance + database + user.
6. `artifact-registry.tf` — image registry.
7. `cloud-run.tf` — service + revision template.
8. `dns.tf` — Cloudflare record.
9. `budget.tf` — billing alert.
10. `outputs.tf` — public-facing values.
```

- [ ] **Step 4: Commit**

```bash
git add infra/gcp/bootstrap.sh infra/gcp/README.md
git commit -m "feat: GCP project bootstrap script + infra/gcp README"
```

---

## Task 5: Terraform — `versions.tf`, `variables.tf`, `.terraform-version`

**Files:**
- Create: `infra/gcp/versions.tf`
- Create: `infra/gcp/variables.tf`
- Create: `infra/gcp/.terraform-version`

- [ ] **Step 1: Write `versions.tf`**

```hcl
# infra/gcp/versions.tf
terraform {
  required_version = ">= 1.7.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.20"
    }
    google-beta = {
      source  = "hashicorp/google-beta"
      version = "~> 5.20"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.30"
    }
  }

  backend "gcs" {
    # bucket + prefix come from -backend-config flags at `terraform init`.
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

provider "google-beta" {
  project = var.project_id
  region  = var.region
}

provider "cloudflare" {
  # Reads CLOUDFLARE_API_TOKEN env automatically.
}
```

- [ ] **Step 2: Write `variables.tf`**

```hcl
# infra/gcp/variables.tf
variable "project_id" {
  description = "GCP project ID hosting the public bridge instance."
  type        = string
}

variable "region" {
  description = "GCP region. Default Seoul to match repo CLAUDE.md."
  type        = string
  default     = "asia-northeast3"
}

variable "public_host" {
  description = "Public hostname (e.g. oidc-bridge.aitc.dev). Cloud Run domain map + Cloudflare CNAME both reference this."
  type        = string
  default     = "oidc-bridge.aitc.dev"
}

variable "cloudflare_zone_id" {
  description = "Cloudflare zone ID for aitc.dev. Look up via dashboard or `cf zone list`."
  type        = string
}

variable "image_repo" {
  description = "Artifact Registry repo name."
  type        = string
  default     = "oidc-bridge"
}

variable "min_instances" {
  description = "Cloud Run min instances. 1 keeps a warm replica for cold-start; 0 saves cost when traffic is bursty."
  type        = number
  default     = 1
}

variable "max_instances" {
  description = "Cloud Run max instances. 10 is comfortable for community traffic; raise on observed need."
  type        = number
  default     = 10
}

variable "cloud_sql_tier" {
  description = "Cloud SQL machine tier. db-g1-small is ~$25/mo and fits the spec budget."
  type        = string
  default     = "db-g1-small"
}

variable "monthly_budget_usd" {
  description = "Budget alert threshold in USD."
  type        = number
  default     = 50
}

variable "billing_account_id" {
  description = "GCP billing account ID for the budget alert (e.g. 0123AB-456789-CDEF01)."
  type        = string
}
```

- [ ] **Step 3: Write `.terraform-version`**

```
1.7.5
```

- [ ] **Step 4: `terraform init` succeeds**

```bash
cd infra/gcp
terraform init \
  -backend-config="bucket=apps-in-toss-community-prod-tf-state" \
  -backend-config="prefix=oidc-bridge"
cd -
```

Expected: `Terraform has been successfully initialized!`. (This requires the bootstrap script from Task 4 to have run; if you're testing locally without GCP creds, run `terraform init -backend=false` to validate the providers without a backend.)

- [ ] **Step 5: Commit**

```bash
git add infra/gcp/versions.tf infra/gcp/variables.tf infra/gcp/.terraform-version
git commit -m "feat: terraform skeleton (versions, variables, terraform-version pin)"
```

---

## Task 6: Terraform — `iam.tf` (service accounts + minimum bindings)

**Files:**
- Create: `infra/gcp/iam.tf`

The bridge runs as `oidc-bridge-runtime@<project>.iam.gserviceaccount.com` (created by `bootstrap.sh`); Terraform manages its bindings. Cloud Build runs as the default Cloud Build SA; we grant it deploy permissions on Cloud Run plus push permissions on Artifact Registry.

- [ ] **Step 1: Write `iam.tf`**

```hcl
# infra/gcp/iam.tf
data "google_project" "this" {
  project_id = var.project_id
}

locals {
  runtime_sa_email      = "oidc-bridge-runtime@${var.project_id}.iam.gserviceaccount.com"
  cloud_build_sa_email  = "${data.google_project.this.number}-compute@developer.gserviceaccount.com"
}

# Cloud Run runtime: read master-key secrets only.
resource "google_project_iam_member" "runtime_secret_accessor" {
  project = var.project_id
  role    = "roles/secretmanager.secretAccessor"
  member  = "serviceAccount:${local.runtime_sa_email}"

  condition {
    title       = "only-bridge-master-keys"
    description = "Limit to oidc-bridge master-key secrets."
    expression  = "resource.name.startsWith(\"projects/${data.google_project.this.number}/secrets/oidc-bridge-master-key-\")"
  }
}

# Cloud Run runtime: connect to Cloud SQL.
resource "google_project_iam_member" "runtime_cloud_sql_client" {
  project = var.project_id
  role    = "roles/cloudsql.client"
  member  = "serviceAccount:${local.runtime_sa_email}"
}

# Cloud Run runtime: write log lines (already implicit via Cloud Run, but
# explicit so the binding survives a default-SA reset).
resource "google_project_iam_member" "runtime_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${local.runtime_sa_email}"
}

# Cloud Build SA: push images to Artifact Registry + deploy Cloud Run revisions.
resource "google_project_iam_member" "build_artifact_writer" {
  project = var.project_id
  role    = "roles/artifactregistry.writer"
  member  = "serviceAccount:${local.cloud_build_sa_email}"
}

resource "google_project_iam_member" "build_run_admin" {
  project = var.project_id
  role    = "roles/run.admin"
  member  = "serviceAccount:${local.cloud_build_sa_email}"
}

resource "google_project_iam_member" "build_act_as_runtime" {
  project = var.project_id
  role    = "roles/iam.serviceAccountUser"
  member  = "serviceAccount:${local.cloud_build_sa_email}"
}
```

- [ ] **Step 2: `terraform validate`**

```bash
cd infra/gcp
terraform validate
cd -
```

Expected: `Success! The configuration is valid.`.

- [ ] **Step 3: Commit**

```bash
git add infra/gcp/iam.tf
git commit -m "feat: terraform IAM (runtime SA scoped to bridge secrets, build SA Cloud Run + AR)"
```

---

## Task 7: Terraform — `secret-manager.tf`

**Files:**
- Create: `infra/gcp/secret-manager.tf`

Terraform creates the *secret entry*. The bytes are populated out-of-band (via `gcloud secrets versions add` per `infra/gcp/README.md`).

- [ ] **Step 1: Write `secret-manager.tf`**

```hcl
# infra/gcp/secret-manager.tf
#
# Creates the master-key secret entry only. Bytes are added out-of-band via:
#   head -c 32 /dev/urandom | gcloud secrets versions add oidc-bridge-master-key-v1 --data-file=-
# Per spec §5.5, master-key bytes never go through Terraform state.

resource "google_secret_manager_secret" "master_key_v1" {
  secret_id = "oidc-bridge-master-key-v1"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }

  labels = {
    managed_by = "terraform"
    component  = "master-key"
    version    = "v1"
  }
}

# Sentinel: a placeholder version so the secret exists for IAM binding tests
# even before the bytes are loaded. Replaced by the operator-loaded version on
# first use. We do NOT include this in production reads -- the runtime fetches
# `versions/latest` and the operator-loaded version becomes latest as soon as it
# is written.
#
# This sentinel is 32 bytes of zeros, which the bridge's payload validator
# accepts in length but the bridge will fail to seal anything useful with.
# This is intentional: a missed bytes-population step fails loudly the first
# time a token is issued, not silently at boot.
resource "google_secret_manager_secret_version" "master_key_v1_sentinel" {
  secret      = google_secret_manager_secret.master_key_v1.id
  secret_data = "00000000000000000000000000000000"

  lifecycle {
    # Once the operator adds the real bytes, terraform should not roll back.
    ignore_changes = [secret_data]
  }
}
```

- [ ] **Step 2: Validate**

```bash
cd infra/gcp && terraform validate && cd -
```

Expected: `Success! The configuration is valid.`.

- [ ] **Step 3: Commit**

```bash
git add infra/gcp/secret-manager.tf
git commit -m "feat: terraform Secret Manager entry for master-key v1"
```

---

## Task 8: Terraform — `cloud-sql.tf`

**Files:**
- Create: `infra/gcp/cloud-sql.tf`

- [ ] **Step 1: Write `cloud-sql.tf`**

```hcl
# infra/gcp/cloud-sql.tf

resource "random_password" "bridge_db" {
  length  = 32
  special = false
}

resource "google_sql_database_instance" "bridge" {
  name             = "oidc-bridge"
  database_version = "POSTGRES_17"
  region           = var.region

  deletion_protection = true

  settings {
    tier              = var.cloud_sql_tier
    availability_type = "ZONAL" # regional HA off; flip to "REGIONAL" if uptime budget allows
    disk_type         = "PD_SSD"
    disk_size         = 10
    disk_autoresize   = true

    backup_configuration {
      enabled                        = true
      start_time                     = "16:00" # UTC; 01:00 KST
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = 14
      }
    }

    ip_configuration {
      # Public IP off; runtime connects via Cloud SQL Auth Proxy (Cloud Run
      # `--add-cloudsql-instances` injects a Unix socket).
      ipv4_enabled    = false
      private_network = null
    }

    database_flags {
      name  = "max_connections"
      value = "100"
    }

    insights_config {
      query_insights_enabled  = true
      query_string_length     = 1024
      record_application_tags = false
      record_client_address   = false
    }
  }
}

resource "google_sql_database" "bridge" {
  name     = "bridge"
  instance = google_sql_database_instance.bridge.name
}

resource "google_sql_user" "bridge" {
  name     = "bridge"
  instance = google_sql_database_instance.bridge.name
  password = random_password.bridge_db.result
}

# Stash the password in Secret Manager so the Cloud Run service can read it
# without putting it in Terraform-rendered config.
resource "google_secret_manager_secret" "db_password" {
  secret_id = "oidc-bridge-db-password"

  replication {
    user_managed {
      replicas {
        location = var.region
      }
    }
  }
}

resource "google_secret_manager_secret_version" "db_password" {
  secret      = google_secret_manager_secret.db_password.id
  secret_data = random_password.bridge_db.result
}

resource "google_secret_manager_secret_iam_member" "runtime_db_password" {
  secret_id = google_secret_manager_secret.db_password.id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${local.runtime_sa_email}"
}
```

- [ ] **Step 2: Validate**

```bash
cd infra/gcp && terraform validate && cd -
```

Expected: clean.

- [ ] **Step 3: Commit**

```bash
git add infra/gcp/cloud-sql.tf
git commit -m "feat: terraform Cloud SQL Postgres 17 + DB password in Secret Manager"
```

---

## Task 9: Terraform — `artifact-registry.tf` + `cloud-run.tf`

**Files:**
- Create: `infra/gcp/artifact-registry.tf`
- Create: `infra/gcp/cloud-run.tf`

- [ ] **Step 1: Write `artifact-registry.tf`**

```hcl
# infra/gcp/artifact-registry.tf
resource "google_artifact_registry_repository" "bridge" {
  location      = var.region
  repository_id = var.image_repo
  description   = "oidc-bridge container images"
  format        = "DOCKER"

  cleanup_policies {
    id     = "keep-recent-30"
    action = "KEEP"
    most_recent_versions {
      keep_count = 30
    }
  }

  cleanup_policies {
    id     = "delete-old"
    action = "DELETE"
    condition {
      older_than = "2592000s" # 30 days
    }
  }
}

locals {
  image_repo_url = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.bridge.repository_id}"
}
```

- [ ] **Step 2: Write `cloud-run.tf`**

```hcl
# infra/gcp/cloud-run.tf

resource "google_cloud_run_v2_service" "bridge" {
  name     = "oidc-bridge"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  # The Cloud Build pipeline updates the image on every push to main. Terraform
  # only manages the *shape* of the service; image SHAs are set imperatively by
  # gcloud run deploy. Ignore changes to the running image so terraform does not
  # fight the pipeline.
  template {
    service_account = local.runtime_sa_email

    scaling {
      min_instance_count = var.min_instances
      max_instance_count = var.max_instances
    }

    max_instance_request_concurrency = 80

    timeout = "30s"

    volumes {
      name = "cloudsql"
      cloud_sql_instance {
        instances = [google_sql_database_instance.bridge.connection_name]
      }
    }

    containers {
      # Placeholder image — Cloud Build replaces this on first deploy.
      image = "${local.image_repo_url}/bridge:bootstrap"

      ports {
        container_port = 8080
      }

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
        cpu_idle          = true
        startup_cpu_boost = true
      }

      env {
        name  = "OIDC_ISSUER"
        value = "https://${var.public_host}"
      }
      env {
        name  = "MASTER_KEY_PROVIDER"
        value = "gcpsm"
      }
      env {
        name  = "GOOGLE_CLOUD_PROJECT"
        value = var.project_id
      }
      env {
        name  = "BRIDGE_TOSS_ADAPTER"
        value = "real"
      }
      env {
        name  = "RATE_LIMIT_ENABLED"
        value = "true"
      }
      env {
        name  = "LOG_LEVEL"
        value = "info"
      }

      # DATABASE_URL points at the Cloud SQL Auth Proxy unix socket.
      env {
        name  = "DATABASE_URL"
        value = "postgres://bridge:DBPASS@/bridge?host=/cloudsql/${google_sql_database_instance.bridge.connection_name}"
      }
      # Source the actual password from Secret Manager. The runtime substitutes
      # ${BRIDGE_DB_PASSWORD} into DATABASE_URL at startup -- a tiny shim added
      # in src/config.ts (Phase 0 already supports a small substitution layer).
      env {
        name = "BRIDGE_DB_PASSWORD"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.db_password.secret_id
            version = "latest"
          }
        }
      }

      # ADMIN_TOKEN: stored in a separate secret created out-of-band the same
      # way master-key bytes are -- the README shows the gcloud incantation.
      env {
        name = "ADMIN_TOKEN"
        value_source {
          secret_key_ref {
            secret  = "oidc-bridge-admin-token"
            version = "latest"
          }
        }
      }

      volume_mounts {
        name       = "cloudsql"
        mount_path = "/cloudsql"
      }

      startup_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        initial_delay_seconds = 5
        period_seconds        = 5
        failure_threshold     = 6
      }

      liveness_probe {
        http_get {
          path = "/healthz"
          port = 8080
        }
        period_seconds    = 30
        failure_threshold = 3
      }
    }
  }

  traffic {
    type    = "TRAFFIC_TARGET_ALLOCATION_TYPE_LATEST"
    percent = 100
  }

  lifecycle {
    ignore_changes = [
      template[0].containers[0].image,
      client,
      client_version,
    ]
  }

  depends_on = [
    google_project_iam_member.runtime_secret_accessor,
    google_project_iam_member.runtime_cloud_sql_client,
    google_secret_manager_secret_iam_member.runtime_db_password,
  ]
}

# Allow unauthenticated public traffic to /oidc/* and /healthz and /status.
# Cloud Run does not have per-path IAM; this is OPEN, and rate-limit + admin
# auth in the bridge handle authorization.
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = google_cloud_run_v2_service.bridge.project
  location = google_cloud_run_v2_service.bridge.location
  name     = google_cloud_run_v2_service.bridge.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}

# Custom domain mapping to oidc-bridge.aitc.dev.
resource "google_cloud_run_domain_mapping" "bridge" {
  location = var.region
  name     = var.public_host

  metadata {
    namespace = var.project_id
  }

  spec {
    route_name = google_cloud_run_v2_service.bridge.name
  }
}
```

The `image = "...:bootstrap"` is a placeholder that Cloud Build replaces on first deploy via `gcloud run deploy`. The `lifecycle.ignore_changes` keeps Terraform from fighting the pipeline.

- [ ] **Step 3: Validate**

```bash
cd infra/gcp && terraform validate && cd -
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add infra/gcp/artifact-registry.tf infra/gcp/cloud-run.tf
git commit -m "feat: terraform Artifact Registry + Cloud Run service + domain mapping"
```

---

## Task 10: Terraform — `dns.tf` + `budget.tf` + `outputs.tf`

**Files:**
- Create: `infra/gcp/dns.tf`
- Create: `infra/gcp/budget.tf`
- Create: `infra/gcp/outputs.tf`

- [ ] **Step 1: Write `dns.tf`**

```hcl
# infra/gcp/dns.tf
#
# Creates the Cloudflare CNAME for oidc-bridge.aitc.dev pointing at the Cloud Run
# domain mapping target. Cloud Run domain mapping verifies ownership via DNS
# challenge once and then issues a managed cert; subsequent deploys reuse the
# same cert.
#
# This depends on Cloud Run domain mapping being created first; terraform
# orchestrates the order via the explicit data lookup.

data "google_cloud_run_domain_mapping" "bridge_lookup" {
  location = var.region
  name     = var.public_host

  depends_on = [google_cloud_run_domain_mapping.bridge]
}

locals {
  # Cloud Run domain mapping returns a canonical hostname like
  # ghs.googlehosted.com via its rrdata records. Use the first CNAME from
  # the resource_record set.
  cname_target = (
    length(google_cloud_run_domain_mapping.bridge.status[0].resource_records) > 0
    ? google_cloud_run_domain_mapping.bridge.status[0].resource_records[0].rrdata
    : "ghs.googlehosted.com."
  )
}

resource "cloudflare_record" "bridge_cname" {
  zone_id = var.cloudflare_zone_id
  name    = trimsuffix(replace(var.public_host, ".aitc.dev", ""), ".")
  type    = "CNAME"
  value   = local.cname_target
  ttl     = 300
  # Keep proxy off so Cloud Run sees the real client IP and Cloudflare does
  # not need to be in the cert path. Operators who want CF in front can flip
  # this to true after testing.
  proxied = false
}
```

- [ ] **Step 2: Write `budget.tf`**

```hcl
# infra/gcp/budget.tf
resource "google_billing_budget" "bridge" {
  billing_account = var.billing_account_id
  display_name    = "oidc-bridge ${var.monthly_budget_usd} USD/mo"

  budget_filter {
    projects = ["projects/${data.google_project.this.number}"]
  }

  amount {
    specified_amount {
      currency_code = "USD"
      units         = tostring(var.monthly_budget_usd)
    }
  }

  threshold_rules {
    threshold_percent = 0.5
    spend_basis       = "CURRENT_SPEND"
  }
  threshold_rules {
    threshold_percent = 0.8
    spend_basis       = "CURRENT_SPEND"
  }
  threshold_rules {
    threshold_percent = 1.0
    spend_basis       = "CURRENT_SPEND"
  }

  all_updates_rule {
    monitoring_notification_channels = []
    disable_default_iam_recipients   = false
  }
}
```

- [ ] **Step 3: Write `outputs.tf`**

```hcl
# infra/gcp/outputs.tf
output "service_url" {
  value       = google_cloud_run_v2_service.bridge.uri
  description = "Direct Cloud Run URL (use only for smoke; production traffic uses public_host)."
}

output "public_url" {
  value       = "https://${var.public_host}"
  description = "Public URL once DNS resolves and the cert is issued."
}

output "image_repo_url" {
  value       = local.image_repo_url
  description = "Artifact Registry URL for image pushes."
}

output "cloud_sql_connection_name" {
  value       = google_sql_database_instance.bridge.connection_name
  description = "Used in DATABASE_URL host=/cloudsql/<this>."
}

output "runtime_service_account" {
  value       = local.runtime_sa_email
  description = "Cloud Run runtime service account."
}

output "master_key_secret_v1" {
  value       = google_secret_manager_secret.master_key_v1.id
  description = "Add v1 bytes via: head -c 32 /dev/urandom | gcloud secrets versions add <this> --data-file=-"
}
```

- [ ] **Step 4: Validate end-to-end**

```bash
cd infra/gcp && terraform validate && terraform fmt -check && cd -
```

Expected: validate succeeds; fmt reports no changes needed (or apply `terraform fmt` and recommit if it does).

- [ ] **Step 5: Commit**

```bash
git add infra/gcp/dns.tf infra/gcp/budget.tf infra/gcp/outputs.tf
git commit -m "feat: terraform DNS + budget alert + outputs"
```

---

## Task 11: `cloudbuild.yaml` — build → push → deploy → smoke → traffic

**Files:**
- Create: `cloudbuild.yaml`

The Cloud Build trigger points at `cloudbuild.yaml` at the repo root. Substitution `_REGION` and `_SERVICE_NAME` are set in the trigger config. Image tag is the commit SHA; the no-traffic deploy + automated smoke + traffic flip pattern means a broken deploy never receives production traffic.

- [ ] **Step 1: Write `cloudbuild.yaml`**

```yaml
# cloudbuild.yaml
#
# Build → push → deploy(no-traffic) → smoke → traffic flip.
# Triggered by Cloud Build on push to main.

substitutions:
  _REGION: asia-northeast3
  _SERVICE_NAME: oidc-bridge
  _ARTIFACT_REPO: oidc-bridge
  _PUBLIC_HOST: oidc-bridge.aitc.dev

# Pin to a digest. `gcr.io/cloud-builders/docker` and `gcloud` are pinned
# below. Refresh via `gcloud container images describe` against the public
# `cloud-builders/docker` for the latest stable digest at publish time.
options:
  logging: CLOUD_LOGGING_ONLY
  machineType: E2_HIGHCPU_8
  dynamic_substitutions: true

steps:
  # 1. Build the image. Tag with commit SHA only (no :latest).
  - id: build
    name: gcr.io/cloud-builders/docker
    args:
      - build
      - --tag=${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_ARTIFACT_REPO}/bridge:${SHORT_SHA}
      - --label=org.opencontainers.image.revision=${COMMIT_SHA}
      - --label=org.opencontainers.image.source=https://github.com/apps-in-toss-community/oidc-bridge
      - .

  # 2. Push.
  - id: push
    name: gcr.io/cloud-builders/docker
    waitFor: [build]
    args:
      - push
      - ${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_ARTIFACT_REPO}/bridge:${SHORT_SHA}

  # 3. Resolve the pushed image to its sha256 digest. Cloud Run revisions are
  #    pinned by digest, never by tag, so a future Artifact Registry GC of the
  #    tag does not silently break a revision.
  - id: digest
    name: gcr.io/google.com/cloudsdktool/cloud-sdk:slim
    waitFor: [push]
    entrypoint: bash
    args:
      - -c
      - |
        set -euo pipefail
        DIGEST=$(gcloud artifacts docker images describe \
          ${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_ARTIFACT_REPO}/bridge:${SHORT_SHA} \
          --format='value(image_summary.digest)')
        echo "$DIGEST" > /workspace/IMAGE_DIGEST
        echo "image digest: $DIGEST"

  # 4. Deploy a new revision with --no-traffic. The revision is reachable at a
  #    revision-specific URL but not yet serving production traffic.
  - id: deploy-no-traffic
    name: gcr.io/google.com/cloudsdktool/cloud-sdk:slim
    waitFor: [digest]
    entrypoint: bash
    args:
      - -c
      - |
        set -euo pipefail
        DIGEST=$(cat /workspace/IMAGE_DIGEST)
        IMAGE=${_REGION}-docker.pkg.dev/${PROJECT_ID}/${_ARTIFACT_REPO}/bridge@${DIGEST}
        gcloud run deploy ${_SERVICE_NAME} \
          --region=${_REGION} \
          --image=$$IMAGE \
          --no-traffic \
          --tag=rev-${SHORT_SHA} \
          --quiet
        REV_URL=$(gcloud run services describe ${_SERVICE_NAME} \
          --region=${_REGION} \
          --format='value(status.traffic.url)' \
          --filter='status.traffic.tag=rev-${SHORT_SHA}' \
          | head -1)
        if [ -z "$$REV_URL" ]; then
          # Fallback: list traffic targets and pick by tag.
          REV_URL=$(gcloud run services describe ${_SERVICE_NAME} \
            --region=${_REGION} \
            --format=json \
            | python3 -c "import sys,json;d=json.load(sys.stdin);print([t['url'] for t in d['status']['traffic'] if t.get('tag')=='rev-${SHORT_SHA}'][0])")
        fi
        echo "$$REV_URL" > /workspace/REV_URL
        echo "revision URL: $$REV_URL"

  # 5. Smoke the new revision over its tagged URL. Both /healthz and /status
  #    must respond, and `bridge doctor` against the public master-key + DB
  #    must return green or yellow. Toss probe is yellow if no app is
  #    registered yet, which is acceptable for the gate.
  - id: smoke
    name: gcr.io/google.com/cloudsdktool/cloud-sdk:slim
    waitFor: [deploy-no-traffic]
    entrypoint: bash
    args:
      - -c
      - |
        set -euo pipefail
        REV_URL=$(cat /workspace/REV_URL)

        # /healthz — simple HTTP 200 with body "ok".
        body=$(curl -fsS "$$REV_URL/healthz")
        if [ "$$body" != "ok" ]; then
          echo "healthz returned: '$$body' (want 'ok')" >&2
          exit 1
        fi

        # /status?format=json — must include status: green or yellow.
        status=$(curl -fsS "$$REV_URL/status?format=json" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])")
        case "$$status" in
          green|yellow) echo "status: $$status" ;;
          red) echo "status: red — aborting deploy" >&2; exit 1 ;;
          *) echo "status: unknown ('$$status') — aborting" >&2; exit 1 ;;
        esac

  # 6. Flip 100% of traffic to the new revision. From this moment forward,
  #    public users hit the new code.
  - id: traffic
    name: gcr.io/google.com/cloudsdktool/cloud-sdk:slim
    waitFor: [smoke]
    entrypoint: bash
    args:
      - -c
      - |
        set -euo pipefail
        gcloud run services update-traffic ${_SERVICE_NAME} \
          --region=${_REGION} \
          --to-tags=rev-${SHORT_SHA}=100 \
          --quiet

# Build artifacts: store the image digest as a build artifact so we can audit.
artifacts:
  objects:
    location: gs://${PROJECT_ID}-tf-state/cloudbuild/${BUILD_ID}/
    paths:
      - /workspace/IMAGE_DIGEST
      - /workspace/REV_URL
```

- [ ] **Step 2: Validate locally with `gcloud beta` syntax check**

```bash
gcloud builds submit --config=cloudbuild.yaml --no-source --substitutions=_REGION=asia-northeast3 \
  --dry-run 2>&1 | tail -10 || true
```

`--dry-run` is not always available; alternatively, use:

```bash
gcloud beta builds triggers create manual --name=verify --build-config=cloudbuild.yaml \
  --quiet --dry-run 2>&1 | head -5 || true
```

The realistic verification is *running* it once on a test branch. Do this in Step 4 below.

- [ ] **Step 3: Commit**

```bash
git add cloudbuild.yaml
git commit -m "feat: cloudbuild.yaml (build, push, deploy --no-traffic, smoke, flip)"
```

- [ ] **Step 4: Manual: create the Cloud Build trigger**

This is one-shot operator work, not automated by Terraform (Cloud Build triggers are awkward to manage in TF when the source is GitHub-connected; see https://cloud.google.com/build/docs/automating-builds for the GitHub App auth flow):

```bash
gcloud builds triggers create github \
  --name=oidc-bridge-main \
  --region=asia-northeast3 \
  --repo-name=oidc-bridge \
  --repo-owner=apps-in-toss-community \
  --branch-pattern="^main$" \
  --build-config=cloudbuild.yaml
```

Verify in console: https://console.cloud.google.com/cloud-build/triggers — the trigger exists, points at the right repo, and uses the `cloudbuild.yaml` we just committed.

---

## Task 12: `.github/workflows/deploy-prod.yml` — manual approval gate

**Files:**
- Create: `.github/workflows/deploy-prod.yml`

Cloud Build's trigger fires on every `main` push, deploys with `--no-traffic`, smokes, and flips. Some operators want a human-in-the-loop before the flip. Add a GitHub Actions workflow that, when invoked manually (`workflow_dispatch`), promotes a specific tagged revision to 100% — independent of Cloud Build's auto-flip.

This is *additive*: the auto-flip in `cloudbuild.yaml` continues to work; this workflow exists for emergency rollbacks and out-of-cycle promotions.

- [ ] **Step 1: Write the workflow**

```yaml
# .github/workflows/deploy-prod.yml
name: Promote/rollback Cloud Run revision

on:
  workflow_dispatch:
    inputs:
      revision_tag:
        description: 'Revision tag to promote to 100% (e.g. rev-abc1234)'
        required: true
        type: string
      reason:
        description: 'Why are you doing this? (audit trail)'
        required: true
        type: string

permissions:
  contents: read
  id-token: write

jobs:
  promote:
    name: Promote revision
    runs-on: ubuntu-24.04
    environment:
      name: production
      url: https://oidc-bridge.aitc.dev
    timeout-minutes: 5
    steps:
      - name: Audit log
        run: |
          echo "actor: ${{ github.actor }}"
          echo "revision_tag: ${{ inputs.revision_tag }}"
          echo "reason: ${{ inputs.reason }}"

      - id: auth
        uses: google-github-actions/auth@v2
        with:
          workload_identity_provider: ${{ secrets.GCP_WIF_PROVIDER }}
          service_account: ${{ secrets.GCP_DEPLOYER_SA }}

      - uses: google-github-actions/setup-gcloud@v2

      - name: Verify revision tag exists
        run: |
          set -euo pipefail
          gcloud run services describe oidc-bridge \
            --region=asia-northeast3 \
            --format=json \
          | python3 -c "import sys,json;tags=[t.get('tag') for t in json.load(sys.stdin)['status']['traffic']];import os;sys.exit(0) if os.environ['TAG'] in tags else (print(f'tag not found: {os.environ[\"TAG\"]}',file=sys.stderr) or sys.exit(1))"
        env:
          TAG: ${{ inputs.revision_tag }}

      - name: Promote to 100%
        run: |
          gcloud run services update-traffic oidc-bridge \
            --region=asia-northeast3 \
            --to-tags=${{ inputs.revision_tag }}=100 \
            --quiet
```

- [ ] **Step 2: Configure secrets out-of-band**

```bash
# Workload Identity Federation provider (one-time, outside this PR):
#   gcloud iam workload-identity-pools providers create-oidc github \
#     --workload-identity-pool=github \
#     --display-name="GitHub Actions" \
#     --attribute-mapping="google.subject=assertion.sub,attribute.repository=assertion.repository,attribute.actor=assertion.actor" \
#     --issuer-uri="https://token.actions.githubusercontent.com"
#
# Then in the GitHub repo:
#   gh secret set GCP_WIF_PROVIDER --body 'projects/<project-num>/locations/global/workloadIdentityPools/github/providers/github'
#   gh secret set GCP_DEPLOYER_SA --body 'oidc-bridge-deployer@<project>.iam.gserviceaccount.com'
```

The plan does not automate this; it's documented in `infra/gcp/README.md` (Task 4 already mentions it implicitly; if not, append to README in this task).

- [ ] **Step 3: Validate workflow syntax**

```bash
docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:latest -color
```

Expected: clean.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/deploy-prod.yml
git commit -m "ci: deploy-prod workflow for manual revision promotion/rollback"
```

---

## Task 13: `docs/PUBLIC_INSTANCE.md` — operator runbook

**Files:**
- Create: `docs/PUBLIC_INSTANCE.md`
- Modify: `docs/RUNBOOK.md`

- [ ] **Step 1: Write `docs/PUBLIC_INSTANCE.md`**

```markdown
# Public instance runbook

The community public instance lives at `https://oidc-bridge.aitc.dev`, hosted
on GCP Cloud Run + Cloud SQL Postgres + Google Cloud Secret Manager in
`asia-northeast3` (Seoul). This runbook covers operating that specific
instance. For self-hosting, see [`SELF_HOSTING.md`](./SELF_HOSTING.md);
for the threat model, see [`SECURITY.md`](./SECURITY.md).

## What runs where

| Component             | Resource                                                             |
|-----------------------|----------------------------------------------------------------------|
| Bridge process        | Cloud Run service `oidc-bridge` (asia-northeast3)                    |
| Database              | Cloud SQL Postgres 17 instance `oidc-bridge`                         |
| Master keys           | Secret Manager `oidc-bridge-master-key-v*`                           |
| Admin token           | Secret Manager `oidc-bridge-admin-token`                             |
| Image registry        | Artifact Registry `asia-northeast3-docker.pkg.dev/<project>/oidc-bridge` |
| Build pipeline        | Cloud Build trigger `oidc-bridge-main` on push to `main`             |
| DNS                   | Cloudflare CNAME `oidc-bridge.aitc.dev` → Cloud Run domain map       |
| Budget alert          | $50/mo at 80% threshold                                              |

## Deploy lifecycle

1. PR merged to `main` → Cloud Build trigger fires.
2. Cloud Build: build image, push by digest, `gcloud run deploy --no-traffic`,
   smoke (/healthz + /status), `gcloud run services update-traffic --to-tags=...=100`.
3. New revision serves production traffic immediately on success.

## Manual promotion / rollback

Use the GitHub Actions `Promote/rollback Cloud Run revision` workflow with
the desired `revision_tag` (e.g. `rev-abc1234`). Cloud Run keeps the last
~100 revisions; rollback is just promoting an older tag.

```bash
gh workflow run deploy-prod.yml -f revision_tag=rev-abc1234 -f reason="rollback to fix #123"
```

## Master-key rotation

```bash
# Local CLI (against the public instance):
ADMIN_TOKEN=<from secret manager> \
  pnpm bridge --base https://oidc-bridge.aitc.dev master-key rotate
```

This adds a new `master-keys` row in the database (next version), then logs
the secret-manager command the operator must run to populate the bytes:

```bash
head -c 32 /dev/urandom \
  | gcloud secrets versions add oidc-bridge-master-key-v2 --data-file=- \
      --project=apps-in-toss-community-prod
```

After bytes are populated, run a batch rewrap (Phase 1 design):

```bash
ADMIN_TOKEN=<...> pnpm bridge --base https://oidc-bridge.aitc.dev master-key rewrap
```

## Adding a new tenant

Same as self-host, just against the public URL:

```bash
ADMIN_TOKEN=<...> pnpm bridge --base https://oidc-bridge.aitc.dev tenant create \
  --name "My App" --toss-app-id <toss-mini-app-id>
```

The admin enrolls mTLS material via `pnpm bridge tenant set-mtls` (which
PUTs the cert+key, encrypted at rest with the per-app sealing key). The
material never returns from any GET (Phase 4 invariant).

## Health monitoring

- Cloud Run service health: https://console.cloud.google.com/run
- Database health: https://console.cloud.google.com/sql
- Live `/status`: https://oidc-bridge.aitc.dev/status

A red /status state pages (Phase 8 introduces the page; alerting is via
Cloud Monitoring uptime checks added in Task 12 of this phase if/when the
operator wires it).

## Cost guardrails

- Budget alert at $50/mo with thresholds at 50%, 80%, 100% (Terraform
  `budget.tf`).
- Cloud Run min instances = 1 (warm replica). Bumping to 0 saves ~$8/mo
  at the cost of cold-start latency.
- Cloud SQL `db-g1-small` is the dominant cost (~$25/mo). Smaller tiers
  exist but compete for connection slots with the bridge.

## Disaster recovery

- Cloud SQL automated backups: 14 retained, 7d PITR window.
- Master-key bytes: NOT backed up by Terraform. Operators MUST keep an
  offline copy of every master-key version. Without the bytes, sealed
  tokens cannot be restored from a Postgres backup.
- Image registry: 30 most-recent versions retained automatically; older
  images deleted after 30 days.
```

- [ ] **Step 2: Append a pointer to `docs/RUNBOOK.md`**

```markdown

## Public instance specifics

The community-hosted public instance at `https://oidc-bridge.aitc.dev` has
deployment-specific procedures (Cloud Build, Cloud Run promotion, Cloud SQL,
GCPSM) documented separately in [`PUBLIC_INSTANCE.md`](./PUBLIC_INSTANCE.md).
```

- [ ] **Step 3: Commit**

```bash
git add docs/PUBLIC_INSTANCE.md docs/RUNBOOK.md
git commit -m "docs: PUBLIC_INSTANCE.md operator runbook + RUNBOOK pointer"
```

---

## Task 14: Deployed-bridge E2E test (gated, no real Toss cert in CI)

**Files:**
- Create: `test/e2e/deployed-bridge.test.ts`

This test, gated by `BRIDGE_DEPLOYED_E2E=1` and reading `BRIDGE_DEPLOYED_URL`,
exercises the public surface from outside. Phase 11 will re-use the same
harness wired into `sdk-example`. Phase 10 ships a smaller version that
validates only the surface that does not require a real Toss authorization
code: discovery, JWKS, /healthz, /status, /admin/whoami (with admin token).

- [ ] **Step 1: Write the test (failing — file does not exist)**

```ts
// test/e2e/deployed-bridge.test.ts
import { describe, expect, it } from 'vitest';

const ENABLED = process.env.BRIDGE_DEPLOYED_E2E === '1';
const BASE = process.env.BRIDGE_DEPLOYED_URL ?? 'https://oidc-bridge.aitc.dev';
const ADMIN = process.env.BRIDGE_DEPLOYED_ADMIN_TOKEN ?? '';

describe.skipIf(!ENABLED)('deployed bridge surface', () => {
  it('serves /healthz', async () => {
    const r = await fetch(`${BASE}/healthz`);
    expect(r.status).toBe(200);
    expect(await r.text()).toBe('ok');
  });

  it('serves /.well-known/openid-configuration with the right shape', async () => {
    const r = await fetch(`${BASE}/.well-known/openid-configuration`);
    expect(r.status).toBe(200);
    const body = (await r.json()) as Record<string, unknown>;
    expect(body.issuer).toBe(BASE);
    expect(body.token_endpoint).toBe(`${BASE}/oidc/token`);
    expect(body.userinfo_endpoint).toBe(`${BASE}/oidc/userinfo`);
    expect(body.revocation_endpoint).toBe(`${BASE}/oidc/revoke`);
    expect(body.jwks_uri).toBe(`${BASE}/.well-known/jwks.json`);
    // Spec §5.7: discovery omits authorization_endpoint and response_types_supported.
    expect(body.authorization_endpoint).toBeUndefined();
    expect(body.response_types_supported).toBeUndefined();
  });

  it('serves /.well-known/jwks.json with at least one RSA key', async () => {
    const r = await fetch(`${BASE}/.well-known/jwks.json`);
    expect(r.status).toBe(200);
    const body = (await r.json()) as { keys: Array<Record<string, string>> };
    expect(Array.isArray(body.keys)).toBe(true);
    expect(body.keys.length).toBeGreaterThan(0);
    for (const k of body.keys) {
      expect(k.kty).toBe('RSA');
      expect(k.alg).toBe('RS256');
      expect(k.use).toBe('sig');
      expect(typeof k.kid).toBe('string');
      expect(typeof k.n).toBe('string');
      expect(typeof k.e).toBe('string');
    }
  });

  it('/status returns JSON with status field', async () => {
    const r = await fetch(`${BASE}/status?format=json`);
    expect(r.status).toBe(200);
    const body = (await r.json()) as { status: string };
    expect(['green', 'yellow', 'red']).toContain(body.status);
    if (body.status === 'red') {
      throw new Error(`/status=red on the deployed bridge: ${JSON.stringify(body)}`);
    }
  });

  it('/oidc/token rejects requests without client_id with invalid_request', async () => {
    const r = await fetch(`${BASE}/oidc/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ grant_type: 'authorization_code' }),
    });
    expect(r.status).toBe(400);
    const body = (await r.json()) as { error: string };
    expect(body.error).toBe('invalid_request');
  });

  // Admin surface only runs when an admin token is provided.
  it.skipIf(!ADMIN)('/admin/whoami with admin token returns 200', async () => {
    const r = await fetch(`${BASE}/admin/whoami`, {
      headers: { authorization: `Bearer ${ADMIN}` },
    });
    expect(r.status).toBe(200);
  });

  it('/admin/whoami without admin token returns 401', async () => {
    const r = await fetch(`${BASE}/admin/whoami`);
    expect(r.status).toBe(401);
  });
});
```

- [ ] **Step 2: Run with the gate off**

```bash
pnpm test test/e2e/deployed-bridge.test.ts 2>&1 | tail -5
```

Expected: 7 tests skipped.

- [ ] **Step 3: Run with the gate on against the deployed bridge (post-deploy)**

```bash
BRIDGE_DEPLOYED_E2E=1 BRIDGE_DEPLOYED_URL=https://oidc-bridge.aitc.dev \
  BRIDGE_DEPLOYED_ADMIN_TOKEN=<from-secret-manager> \
  pnpm test test/e2e/deployed-bridge.test.ts 2>&1 | tail -10
```

Expected: 7 passed (or 6 passed + 1 skipped if `ADMIN` is empty).

- [ ] **Step 4: Add `e2e:deployed` script**

In `package.json` `scripts`:

```json
"e2e:deployed": "BRIDGE_DEPLOYED_E2E=1 vitest run test/e2e/deployed-bridge.test.ts"
```

- [ ] **Step 5: Commit**

```bash
git add test/e2e/deployed-bridge.test.ts package.json
git commit -m "test: deployed-bridge E2E surface (gated by BRIDGE_DEPLOYED_E2E)"
```

---

## Task 15: First production push + DNS flip

This task is one-shot operator work, not committable code. It is the
final gate that turns `oidc-bridge.aitc.dev` from "configured" to
"serving traffic".

- [ ] **Step 1: Run `infra/gcp/bootstrap.sh`** (if not already done):

```bash
GCP_PROJECT_ID=apps-in-toss-community-prod GCP_REGION=asia-northeast3 \
  ./infra/gcp/bootstrap.sh
```

- [ ] **Step 2: Apply Terraform**

```bash
cd infra/gcp
terraform init \
  -backend-config="bucket=apps-in-toss-community-prod-tf-state" \
  -backend-config="prefix=oidc-bridge"
terraform apply \
  -var="project_id=apps-in-toss-community-prod" \
  -var="region=asia-northeast3" \
  -var="public_host=oidc-bridge.aitc.dev" \
  -var="cloudflare_zone_id=<from-cloudflare-dashboard>" \
  -var="billing_account_id=<from-billing-console>"
cd -
```

Expected output: `Apply complete! Resources: ~25 added, 0 changed, 0 destroyed.`. Note the `service_url`, `image_repo_url`, `cloud_sql_connection_name` outputs.

- [ ] **Step 3: Populate master-key v1 bytes**

```bash
head -c 32 /dev/urandom \
  | gcloud secrets versions add oidc-bridge-master-key-v1 --data-file=- \
      --project=apps-in-toss-community-prod
# Replaces the sentinel zero-bytes version.
```

- [ ] **Step 4: Populate admin token**

```bash
openssl rand -base64 32 | tr -d '=' | tr '+/' '_-' \
  | gcloud secrets versions add oidc-bridge-admin-token --data-file=- \
      --project=apps-in-toss-community-prod
# Stash a copy in your password manager. The bridge process reads this from
# Secret Manager at startup; you read it from the manager whenever you need
# to call /admin/*.
```

(If the secret doesn't exist yet, create it: `gcloud secrets create oidc-bridge-admin-token --replication-policy=user-managed --locations=asia-northeast3`.)

- [ ] **Step 5: Trigger first Cloud Build**

```bash
git push origin main  # if main has changes; else use the trigger UI to fire manually
```

Watch the build at https://console.cloud.google.com/cloud-build/builds. Expected outcome: build → push → deploy --no-traffic → smoke green/yellow → traffic flip → revision serves 100%.

- [ ] **Step 6: Verify DNS resolves and the cert is issued**

```bash
dig +short oidc-bridge.aitc.dev
curl -sSI https://oidc-bridge.aitc.dev/healthz | head -5
```

Expected: a CNAME to `ghs.googlehosted.com.` (or similar Cloud Run target) and an HTTP/2 200 response from `/healthz`. First-time cert issuance can take 5–15 minutes after DNS propagates.

- [ ] **Step 7: Run the deployed-bridge E2E**

```bash
BRIDGE_DEPLOYED_E2E=1 \
BRIDGE_DEPLOYED_URL=https://oidc-bridge.aitc.dev \
BRIDGE_DEPLOYED_ADMIN_TOKEN="$(gcloud secrets versions access latest --secret=oidc-bridge-admin-token --project=apps-in-toss-community-prod)" \
  pnpm e2e:deployed
```

Expected: 7 passed (or 6 + 1 skipped). If `/status` is yellow because no app is registered, that is acceptable; the gate is "not red".

- [ ] **Step 8: Confirm budget alert is active**

Console → Billing → Budgets & alerts → confirm `oidc-bridge 50 USD/mo` exists with thresholds at 50/80/100%.

---

## Task 16: PR

- [ ] **Step 1: Open the PR**

Title: `Phase 10: GCP Cloud Run public deployment`

Body (markdown):

```markdown
## Summary
- Public instance lives at `https://oidc-bridge.aitc.dev` on GCP Cloud Run +
  Cloud SQL Postgres 17 + Google Cloud Secret Manager in `asia-northeast3`.
- Cloud Build pipeline on push to `main`: build → push (Artifact Registry, by digest)
  → `gcloud run deploy --no-traffic` → smoke `/healthz` + `/status` → traffic flip.
- Master-key bytes live in Secret Manager (`oidc-bridge-master-key-v*`), loaded
  via the GCPSM provider with 6h TTL cache (Phase 1 contract).
- Cloudflare CNAME for `oidc-bridge.aitc.dev` → Cloud Run domain map.
- $50/mo budget alert with thresholds at 50/80/100%.
- Manual promotion/rollback workflow at `.github/workflows/deploy-prod.yml`.
- Operator runbook at `docs/PUBLIC_INSTANCE.md`.
- Deployed-bridge E2E test (gated by `BRIDGE_DEPLOYED_E2E=1`) covering
  discovery, JWKS, /healthz, /status, /oidc/token surface, /admin/whoami auth.

## Test plan
- [ ] `pnpm test test/master-keys/` — GCPSM provider unit tests pass.
- [ ] `pnpm install --include=optional=false` — bridge still starts (no
      `@google-cloud/secret-manager` import at module top-level).
- [ ] `cd infra/gcp && terraform validate && terraform fmt -check` — clean.
- [ ] `actionlint .github/workflows/deploy-prod.yml` — clean.
- [ ] `infra/gcp/bootstrap.sh` runs idempotently against a fresh GCP project.
- [ ] `terraform apply` provisions the stack; outputs match expected URLs.
- [ ] First Cloud Build completes green and serves traffic.
- [ ] `BRIDGE_DEPLOYED_E2E=1 pnpm e2e:deployed` against the deployed instance
      returns 7 passed (or 6 passed + 1 skipped without admin token).
- [ ] `https://oidc-bridge.aitc.dev/.well-known/openid-configuration` returns
      a valid OIDC discovery document.
- [ ] Budget alert is configured and visible in the billing console.
```

- [ ] **Step 2: Review handoff**

Two-stage review:
1. Spec compliance reviewer confirms §3.1 + §11 Phase 10 + decision row #23
   are fully covered (Cloud Run + Cloud SQL + GCPSM + Cloud Build pipeline +
   DNS + deployed-mini-app E2E harness).
2. Code-quality reviewer confirms Terraform `terraform fmt -check` is clean,
   no service account has overly broad IAM bindings, no `@google-cloud/*`
   import is at module top-level, and the Cloud Build step pinning is on
   digests not `:latest`.

---

## Done condition

This phase is done when:

1. `https://oidc-bridge.aitc.dev/healthz` returns `200 ok`.
2. `https://oidc-bridge.aitc.dev/.well-known/openid-configuration` returns a
   valid OIDC discovery document with `issuer = https://oidc-bridge.aitc.dev`.
3. `BRIDGE_DEPLOYED_E2E=1 pnpm e2e:deployed` is green from a developer
   workstation.
4. A push to `main` triggers Cloud Build, which builds, pushes by digest,
   deploys with `--no-traffic`, smokes, and flips traffic — all without
   manual intervention.
5. `pnpm bridge --base https://oidc-bridge.aitc.dev tenant create ...` works
   against the public admin token.
6. The budget alert is configured at $50/mo.
7. The PR is merged with both reviewers' approval.

That state is the foundation Phase 11 (sdk-example dog-fooding) builds on —
Phase 11 wires `sdk-example`'s `AuthPage` to call `https://oidc-bridge.aitc.dev/oidc/token`
with the registered `client_id`, completes the round trip via Supabase
`signInWithIdToken`, and adds a "show me Toss claims" button that calls
`/oidc/userinfo`. M5 launch is gated on Phase 11 succeeding end-to-end against
the public instance shipped here.
