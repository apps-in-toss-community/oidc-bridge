# Self-hosting oidc-bridge

This walkthrough takes a clean machine to a working bridge in under five
minutes. It uses **sqlite + file-backed master key**, which is the right
choice for a single-app self-host. Larger deployments can swap in Postgres
(`STORAGE=pg`, `DATABASE_URL=…`) and a hosted secret manager
(`MASTER_KEY_PROVIDER=gcpsm` or `file`) without touching application code.

The `bootstrap` and `doctor` commands enforce the assumptions described
in the [zero-code mode design](./superpowers/specs/2026-05-01-oidc-bridge-zero-code-mode-design.md);
this doc is the operator-facing summary.

## Prerequisites

- Node 24 LTS, pnpm 10.33.0
- An RSA-2048 private key in PKCS#8 PEM (used to sign id_tokens)
- A Toss sandbox / production mTLS cert + key per app you'll register
  (issued from the Toss console, ~390-day validity)

## 1. Build

```bash
git clone https://github.com/apps-in-toss-community/oidc-bridge.git
cd oidc-bridge
pnpm install
pnpm build
```

This produces `dist/server.mjs` (the HTTP server) and `dist/cli.mjs` (the
admin CLI). The rest of this doc invokes the CLI as `oidc-bridge` —
substitute `node dist/cli.mjs` if you haven't put the built CLI on your
PATH.

## 2. Bootstrap

```bash
oidc-bridge bootstrap \
  --db-path ./data/oidc-bridge.sqlite \
  --master-key-dir ./data/master-keys \
  --email you@example.com \
  --workspace default \
  --issuer-hint https://oidc-bridge.example.com
```

The command:

1. Creates the SQLite database (running migrations).
2. Generates a fresh 32-byte master key at `<master-key-dir>/v1.key`
   (mode 0600).
3. Inserts the first user, the first workspace, and a root admin
   API token.
4. Prints a one-time block of values you must save **right now**:

```
Bootstrap complete.

Save these values now — the API token plaintext will not be shown again.

  USER_ID=user_…
  WORKSPACE_ID=ws_…
  API_TOKEN_ID=tok_…
  ADMIN_API_TOKEN=tok_…
  MASTER_KEY_PATH=./data/master-keys/v1.key  (mode 600)

Add to your bridge .env:

  STORAGE=sqlite
  SQLITE_PATH=./data/oidc-bridge.sqlite
  MASTER_KEY_PROVIDER=file
  MASTER_KEY_DIR=./data/master-keys
  OIDC_ISSUER=https://oidc-bridge.example.com
  OIDC_ACTIVE_KID=k1
  OIDC_SIGNING_KEY_K1_PEM="$(cat your-signing-key.pem)"
  API_TOKEN=tok_…

Next: run `oidc-bridge doctor` to verify the install.
```

`bootstrap` refuses to run a second time against the same master-key
directory or DB — re-bootstrapping would lose access to existing sealed
tokens. To start over, delete both `--db-path` and `--master-key-dir`
first, knowing that any sealed tokens in the wild become unrecoverable.

## 3. Generate (or supply) a signing key

If you don't have one:

```bash
node -e 'import("node:crypto").then(({generateKeyPairSync})=>{const {privateKey}=generateKeyPairSync("rsa",{modulusLength:2048});process.stdout.write(privateKey.export({format:"pem",type:"pkcs8"}).toString())})' \
  > ./data/signing-key-k1.pem
```

The bootstrap output assumed `OIDC_ACTIVE_KID=k1`. The kid name is
arbitrary — the env-var slot (`K1`) and the kid string just need to match
(case-insensitive; the env var is uppercased, the kid lowercased).

## 4. Write `.env`

Paste the block from step 2 into a `.env` file (or your secret store) and
fill in the signing key:

```env
STORAGE=sqlite
SQLITE_PATH=./data/oidc-bridge.sqlite
MASTER_KEY_PROVIDER=file
MASTER_KEY_DIR=./data/master-keys
OIDC_ISSUER=https://oidc-bridge.example.com
OIDC_ACTIVE_KID=k1
OIDC_SIGNING_KEY_K1_PEM="-----BEGIN PRIVATE KEY-----
…
-----END PRIVATE KEY-----
"
API_TOKEN=tok_<plaintext from bootstrap>
```

## 5. Verify with `doctor`

```bash
oidc-bridge doctor
```

The command runs five probes and prints a report:

| Probe | Green means |
|---|---|
| `env` | All required env vars present and well-formed |
| `db` | The configured DB is reachable and migrated |
| `master-key` | `v1.key` is present, ≥32 bytes, mode 600 |
| `jwks` | The active signing key signs and verifies an RS256 JWT |
| `toss` | mTLS handshake to Toss reaches `/login-me` |

`yellow` is "non-fatal warning" — for example, the `toss` probe is
yellow if you didn't pass `--cert` and `--key`, because it has nothing
to handshake with. `doctor` exits 0 on green or yellow, 1 on red.

To exercise the Toss leg too:

```bash
oidc-bridge doctor \
  --cert ./local/sandbox.cert.pem \
  --key ./local/sandbox.key.pem
```

You don't need a valid Toss access token — the probe sends a placeholder
and treats Toss returning a `FAIL` envelope (e.g. `INVALID_TOKEN`) as a
**green** result, because that proves the mTLS handshake worked. Only a
network/TLS failure is red.

`--json` forces JSON output even on a TTY (handy for CI piping):

```bash
oidc-bridge doctor --json | jq '.'
```

## 6. Start the server

```bash
node dist/server.mjs
```

By default this binds to `0.0.0.0:8080`. Put a TLS-terminating reverse
proxy (Caddy, nginx, Traefik) in front of it. The bridge does not
terminate TLS itself.

## 7. Add your first app

Once the server is running, register a Toss mini-app:

```bash
export ADMIN_API_TOKEN=tok_<plaintext from step 2>

oidc-bridge app create \
  --workspace-id ws_<from step 2> \
  --app-id-toss <toss-mini-app-id> \
  --title my-mini-app \
  --cert ./local/sandbox.cert.pem \
  --key ./local/sandbox.key.pem \
  --allowed-origin https://my-mini-app.example.com
```

The mTLS PEMs are sealed inside the `apps` row using a key derived from
`v1.key`; they never leave the bridge.

## Backups & disaster recovery

Two files contain everything that is hard to reproduce:

1. `<master-key-dir>/v*.key` — every key version. Lose this and **every
   sealed mTLS PEM and every `ait_*` token in flight becomes
   unrecoverable**.
2. `<sqlite-path>` — every workspace, app, user, api-token, and master-
   key row.

Back up both. If you only back up the DB, you can't decrypt it.

`v1.key` rotation is a Phase 9 / 10 concern (`master-key rotate`); for
now treat the file as long-lived.

## Troubleshooting

- `doctor` reports `db: red` → `SQLITE_PATH` points at a missing or
  corrupt file. Re-run `bootstrap` against a fresh path or restore from
  backup.
- `doctor` reports `master-key: yellow` → the file's mode is wider than
  0600. `chmod 600 <master-key-dir>/v1.key`.
- `doctor` reports `jwks: red` → either the active kid isn't in env, or
  the PEM isn't a valid PKCS#8 RSA key. Regenerate per step 3.
- `doctor` reports `toss: red` → mTLS handshake failed. Verify the cert
  + key match (`openssl x509 -in cert.pem -modulus | openssl md5` and
  `openssl rsa -in key.pem -modulus | openssl md5` should match) and
  that the cert is registered in the Toss console.

For ongoing operations (rotating signing keys, adding confidential
clients, capturing fresh Toss fixtures), see [`RUNBOOK.md`](./RUNBOOK.md).
