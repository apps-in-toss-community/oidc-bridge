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
2. Pick a kid (e.g. `2026-05-15-a` — the date helps audit). Set:
   ```
   OIDC_SIGNING_KEY_2026-05-15-A_PEM=<contents of new-key.pem>
   ```
   The kid in env names is uppercased; the registry lowercases it. Match the
   value you pick for `OIDC_ACTIVE_KID`.
3. Restart the bridge **without** changing `OIDC_ACTIVE_KID`. The new key is
   now in JWKS but not yet signing. Verify:
   ```bash
   curl -s https://oidc-bridge.aitc.dev/.well-known/jwks.json | jq '.keys[].kid'
   ```
4. Wait at least 6 hours so consumer JWKS caches see the new kid.
5. Set `OIDC_ACTIVE_KID=2026-05-15-a` and restart. New id_tokens sign with the
   new key. Consumers verify with whichever key matches the token's kid.
6. After 24 hours of new-token-only signing, drop the old key env and restart.
