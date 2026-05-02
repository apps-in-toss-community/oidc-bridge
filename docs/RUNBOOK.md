# RUNBOOK — oidc-bridge

Operational procedures for the community-operated public instance and
self-host deployments. Each section is self-contained — read top-to-bottom for
the procedure you're running.

## Rotating OIDC signing keys

The bridge supports overlapping signing keys. Add the new key first, switch the
active kid, then drop the old key after consumers' JWKS caches expire (typical
TTL: 5 minutes; max observed: 1 hour).

1. Generate a new RSA-2048 PEM (PKCS#8):
   ```bash
   node -e 'import("node:crypto").then(({generateKeyPairSync})=>{const {privateKey}=generateKeyPairSync("rsa",{modulusLength:2048});process.stdout.write(privateKey.export({format:"pem",type:"pkcs8"}).toString())})' > new-key.pem
   ```
2. Set the new key as `OIDC_SIGNING_KEY_K2_PEM` (the deploy workflow already
   knows about K1 and K2 slots — see `.github/workflows/deploy.yml`). On
   second and later rotations, write the new key into whichever slot was
   just retired — see step 6's slot-swap convention. Pick a kid value for
   `OIDC_ACTIVE_KID` later. Convention: short stable slot names for env
   vars (`K1`, `K2`); the kid value carried inside JWKS / `id_token` header
   can be anything (e.g. `2026-05-15-a` — date helps audit). The kid in
   env-var names is uppercased; the registry lowercases it.
3. Restart the bridge **without** changing `OIDC_ACTIVE_KID` (still `k1`).
   The new K2 key is now in JWKS but not yet signing. Verify:
   ```bash
   curl -s https://oidc-bridge.aitc.dev/.well-known/jwks.json | jq '.keys[].kid'
   ```
4. Wait at least 6 hours so consumer JWKS caches see the new kid.
5. Set `OIDC_ACTIVE_KID=k2` and restart. New id_tokens sign with K2.
   Consumers verify with whichever key matches the token's kid.
6. After 24 hours of new-token-only signing, drop the old K1 secret and
   restart. To rotate again later, swap the slots: the now-retired K1 slot
   becomes the home for the next new key.

Need more than two overlapping keys at once? Add an `OIDC_SIGNING_KEY_K3_PEM`
secret AND extend the `env:` + `emit` blocks in `.github/workflows/deploy.yml`
to include it. Leave it out of the missing-check loop — extra slots stay
optional so deploys succeed when only K1+K2 are set.

## Adding a confidential client (Edge Function operator)

Confidential clients hold a `client_secret` and authenticate `/oidc/token`
calls with `client_secret_basic` or `client_secret_post`. They do **not** use
the `Origin` header for auth.

1. Issue a secret via the admin CLI:
   ```bash
   oidc-bridge app rotate-secret --app-id app_abc
   ```
   The plaintext is shown **once**. Store it in your operator's secret store
   (Supabase Edge Function secret, GCP Secret Manager, etc.).
2. Use `client_secret_basic` from the operator:
   ```ts
   const auth = `Basic ${btoa(`${clientId}:${clientSecret}`)}`;
   await fetch(`${BRIDGE}/oidc/token`, {
     method: 'POST',
     headers: { authorization: auth, 'content-type': 'application/x-www-form-urlencoded' },
     body: new URLSearchParams({
       grant_type: 'authorization_code',
       code: authorizationCode,
       client_id: clientId,
     }),
   });
   ```
3. Rotation overlap: `app rotate-secret` adds a new hash and keeps the old
   one. Both are accepted until you call:
   ```bash
   oidc-bridge app rotate-secret --app-id app_abc --drop-previous
   ```

Confidential clients can have `allowed_origins` empty — Origin is ignored
when an `Authorization: Basic` header is present.

## Enabling raw-tokens for an app

Raw-tokens (`GET /oidc/raw-tokens`) returns the underlying Toss access token.
Default-off; opt in per app:

```bash
oidc-bridge app raw-tokens --app-id app_abc --enable
```

The endpoint never returns the refresh token. To refresh, the operator calls
`/oidc/token grant_type=refresh_token` — Bridge stays the lifecycle authority.

Disable:
```bash
oidc-bridge app raw-tokens --app-id app_abc --disable
```

When disabled, `GET /oidc/raw-tokens` returns 404 — the route looks absent for
that app.

## Revoking tokens

`POST /oidc/revoke` accepts:
- `token=ait_<access_token> token_type_hint=access_token` — local-only mark.
- `token=ait_<refresh_token> token_type_hint=refresh_token` — local mark + Toss `/access-remove`.

Always returns 200. The local revocation list is per-instance in-memory;
restarting the bridge clears it. For a permanent kill switch in self-host,
rotate the master key (the old wrapper version becomes unrecoverable once you
remove the old key bytes).
