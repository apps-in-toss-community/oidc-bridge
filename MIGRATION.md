# Migration: `/verify` → `/oidc/token` (M1)

This release is a breaking change. The single-`/verify` endpoint and the
HTTP-Basic-Auth-against-Toss assumption are both gone, replaced by a
multi-tenant OIDC + mTLS architecture.

If you operate a self-hosted bridge, follow the steps below before
upgrading.

## What's changed

| Before (M0.5) | After (M1) |
|---|---|
| `POST /verify` | `POST /oidc/token`, `GET /oidc/userinfo`, `POST /oidc/revoke` |
| HTTP Basic Auth toward Toss | mTLS toward Toss (per-tenant cert+key) |
| `TOSS_CLIENT_ID` / `TOSS_CLIENT_SECRET` env vars | per-tenant records in the tenant store |
| Single global identity | Multiple tenants, each with `client_id` / `client_secret` |
| Plain `claims` JSON response | OIDC-standard `id_token` (RS256), `access_token` (sealed `aitc_…`), `refresh_token` |
| No discovery doc, no JWKS | `/.well-known/openid-configuration`, `/.well-known/jwks.json` |

## What you need to do

1. **Generate an mTLS cert+key.** Apps-in-Toss console → mTLS 인증서 →
   +발급받기. Save the two PEM files.
2. **Generate bridge secrets.**
   ```
   openssl rand -base64 32        # → OIDC_MASTER_KEY
   openssl rand -hex 32           # → ADMIN_TOKEN
   openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
                                  # → OIDC_SIGNING_KEY (paste full PEM)
   ```
3. **Update `.env`.** See the new `.env.example`. Remove
   `TOSS_CLIENT_ID` and `TOSS_CLIENT_SECRET`; they are no longer read.
4. **Provision your first tenant.** Two options:

   **Online** (bridge already running with the new env vars):
   ```
   oidc-bridge --bridge https://my-bridge.example.com \
     --admin-token "$ADMIN_TOKEN" \
     tenant create \
     --name "my-mini-app" \
     --environment production \
     --cert ./client-cert.pem \
     --key ./client-key.pem
   ```

   **Offline** (no bridge running yet — useful for first-time bootstrap):
   ```
   oidc-bridge --offline --data-dir /var/lib/oidc-bridge \
     tenant create \
     --name "my-mini-app" \
     --environment production \
     --cert ./client-cert.pem \
     --key ./client-key.pem
   ```

   Save the printed `client_id` and `client_secret`. The secret is shown
   exactly once; the bridge stores only a bcrypt hash.

5. **Update consumer code.** Replace `POST /verify` with `POST /oidc/token`
   using `grant_type=authorization_code` and `client_secret_basic` auth.
   See README "Supabase Edge Function" snippet for the canonical example.

## What stays the same

- The Docker image and `docker-compose.yml` shape.
- Caddy auto-HTTPS in front of the bridge.
- The mini-app's `appLogin()` call producing `{ authorizationCode, referrer }`.

## Rolling back

The bridge is Type C (no semver contract). Pin a previous image tag in
`docker-compose.yml`:

```yaml
services:
  app:
    image: ghcr.io/apps-in-toss-community/oidc-bridge:sha-<previous>
```

Tenant data on the Docker volume is independent of the image, so a
roll-back doesn't touch it.

## Questions

Open an issue at <https://github.com/apps-in-toss-community/oidc-bridge>.
