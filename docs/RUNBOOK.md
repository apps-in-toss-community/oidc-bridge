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
   knows about K1 and K2 slots — see `.github/workflows/deploy.yml`). Pick a
   kid value for `OIDC_ACTIVE_KID` later. Convention: short stable slot names
   for env vars (`K1`, `K2`); the kid value carried inside JWKS / `id_token`
   header can be anything (e.g. `2026-05-15-a` — date helps audit). The kid
   in env-var names is uppercased; the registry lowercases it.
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
secret AND extend the `env:` + missing-check + `emit` blocks in
`.github/workflows/deploy.yml` to include it.
