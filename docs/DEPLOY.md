# Deployment guide — community Vultr Seoul instance

This is the runbook for the **community-operated public instance** of
`oidc-bridge`. Self-hosters can follow the same steps on any provider; the
Docker image and the compose stack are not Vultr-specific.

> **Reminder:** the community instance is rate-limited, best-effort, and has
> no SLA. Production workloads should self-host.

The end state is:

- One Vultr VPS in Seoul (ICN), running Docker.
- `/opt/oidc-bridge/` contains `docker-compose.yml`, `Caddyfile`, `.env`.
- Caddy terminates TLS for `bridge.<your-domain>` and proxies to the bridge.
- A GitHub Actions workflow rebuilds the image on every push to `main`,
  pushes to GHCR, then SSHs into the VPS and runs `docker compose pull && up -d`.

Once that is set up, day-to-day operation is "merge to main".

---

## 1. Provision a Vultr VPS

1. Sign in / sign up at <https://www.vultr.com>.
2. **Deploy New Server** → Cloud Compute → **Seoul (ICN)**.
3. Plan: **Regular Cloud Compute, 1 vCPU / 1 GB RAM / 25 GB NVMe** (`vc2-1c-1gb`, ~$5/mo).
   The bridge is stateless and IO-bound; this size is comfortable for the
   community traffic budget.
4. OS: **Ubuntu 24.04 LTS**.
5. Add your SSH public key under "SSH Keys". Disable password auth at
   creation if Vultr offers the option.
6. Hostname: anything (e.g. `oidc-bridge-icn-1`).

After ~60 seconds the VPS is up. Note its public IPv4.

## 2. Initial security hardening

SSH in as `root` first, then create a non-root deploy user:

```sh
ssh root@<VPS_IP>

adduser --disabled-password --gecos "" deploy
usermod -aG sudo deploy
mkdir -p /home/deploy/.ssh
cp /root/.ssh/authorized_keys /home/deploy/.ssh/authorized_keys
chown -R deploy:deploy /home/deploy/.ssh
chmod 700 /home/deploy/.ssh
chmod 600 /home/deploy/.ssh/authorized_keys
```

Disable root SSH login and password auth:

```sh
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
systemctl restart ssh
```

Firewall (UFW) — allow SSH + HTTP + HTTPS only:

```sh
ufw allow OpenSSH
ufw allow 80/tcp
ufw allow 443/tcp
ufw allow 443/udp   # HTTP/3
ufw --force enable
```

`fail2ban` for SSH brute-force protection:

```sh
apt-get update
apt-get install -y fail2ban
systemctl enable --now fail2ban
```

Unattended security updates:

```sh
apt-get install -y unattended-upgrades
dpkg-reconfigure -plow unattended-upgrades   # answer Yes
```

Log out, then verify you can SSH in as `deploy` (not `root`):

```sh
ssh deploy@<VPS_IP>
```

## 3. Install Docker

As `deploy` on the VPS:

```sh
curl -fsSL https://get.docker.com | sudo sh
sudo usermod -aG docker deploy
# Log out and back in so the group membership takes effect.
exit
ssh deploy@<VPS_IP>
docker compose version   # should print v2.x
```

`docker compose` v2 is bundled with the Docker package — no separate
install needed.

## 4. Domain + DNS

Pick a hostname for the bridge, e.g. `bridge.apps-in-toss-community.org`
(replace with whatever you control — the org may not own that domain yet).

Create an `A` record pointing the hostname at the VPS public IPv4. Caddy
will fetch a Let's Encrypt cert on first request, so DNS must resolve
**before** you bring the stack up.

Verify:

```sh
dig +short bridge.<your-domain>
```

Should return the VPS IP.

## 5. Place the `.env` on the VPS

```sh
sudo mkdir -p /opt/oidc-bridge
sudo chown deploy:deploy /opt/oidc-bridge
cd /opt/oidc-bridge
```

`docker-compose.yml` and `Caddyfile` are synced automatically by the
deploy workflow on every push to `main` (see § 8) — you do not place
them by hand. Only `.env` is managed out-of-band, because it holds
secrets and the workflow has no business touching them:

```sh
# On the VPS, create /opt/oidc-bridge/.env from the .env.example in this repo.
# Edit it to set:
#   ACME_EMAIL              — your ops email
#   TOSS_CLIENT_ID          — partner credential
#   TOSS_CLIENT_SECRET      — partner credential
#   RATE_LIMIT_ENABLED=true — for the public instance; flip to false on
#                             self-hosts that want unrestricted traffic
nano .env
```

For self-hosts that need `/firebase-token`, also set
`FIREBASE_SERVICE_ACCOUNT` (raw JSON or base64). The community public
instance does **not** carry an end-user Firebase service account.

The repo's `Caddyfile` ships with `oidc-bridge.aitc.dev` baked in
because that is the community public instance hostname. Self-hosters
running their own deploy workflow against a fork should change it to
their own hostname (and commit, so `main` carries it). Alternatively,
keep a local-only `Caddyfile` on your VPS and remove `Caddyfile` from
the workflow's `source:` list so the sync step does not overwrite it.

## 6. GitHub repo secrets

In the repo: **Settings → Secrets and variables → Actions → New repository
secret**. Add:

| Name | Value |
|---|---|
| `VULTR_HOST` | VPS public IPv4 (or DNS name) |
| `VULTR_USER` | `deploy` |
| `VULTR_SSH_KEY` | private key whose public half is in `~deploy/.ssh/authorized_keys` |

`VULTR_SSH_KEY` must be the full PEM block (including the
`-----BEGIN ... PRIVATE KEY-----` header). Generate a dedicated key for
GitHub Actions rather than reusing your personal key:

```sh
ssh-keygen -t ed25519 -f gha-deploy -C "gha-deploy@oidc-bridge"
ssh-copy-id -i gha-deploy.pub deploy@<VPS_IP>
# Paste the contents of `gha-deploy` into the VULTR_SSH_KEY secret.
```

`GITHUB_TOKEN` is provided automatically; no GHCR PAT is needed.

## 7. First boot

On the VPS:

```sh
cd /opt/oidc-bridge

# First pull may take a moment — the image is built by the deploy workflow,
# so trigger one push to main first (or run the workflow manually from the
# Actions tab) to get the `:latest` tag populated.
docker compose pull
docker compose up -d
docker compose ps   # both services should be running; app should be healthy
```

Smoke-test from your laptop:

```sh
curl -i https://bridge.<your-domain>/healthz
# HTTP/2 200
# {"status":"ok"}
```

The first request triggers ACME — give Caddy ~30s to obtain the cert.

## 8. Day-to-day: just merge to main

After the first manual boot, every subsequent push to `main`:

1. CI builds and tests the code (`.github/workflows/ci.yml`).
2. The deploy workflow (`.github/workflows/deploy.yml`) builds the image,
   pushes `ghcr.io/apps-in-toss-community/oidc-bridge:latest` and `:sha-<sha>`,
   then SSHs in and runs `docker compose pull && up -d`.
3. The workflow waits for the new container to report `healthy` before
   declaring success.

To roll back, SSH in and pin to a known-good SHA:

```sh
cd /opt/oidc-bridge
# Edit docker-compose.yml: change the image tag from :latest to :sha-<good-sha>
docker compose pull
docker compose up -d
```

## 9. Logs and ops

```sh
docker compose logs -f app
docker compose logs -f caddy
docker compose ps
docker compose restart app
```

The bridge is stateless — any restart is safe. Caddy's certs and ACME
account live in the `caddy_data` volume; do not delete that volume unless
you intend to re-issue.

---

## Scaling out (future)

The bridge is designed to scale horizontally: it has no DB, no shared
session store, and the rate-limit counters are in-memory per instance. To
go beyond one VPS:

### Option A — Vultr Load Balancer (managed, ~$10/mo)

1. Provision N VPSs in Seoul, each with the same `/opt/oidc-bridge/` setup.
2. Create a Vultr Load Balancer in the same region. Backends: the N VPSs
   on port 443, sticky sessions off (the bridge is stateless).
3. Point your DNS at the load balancer instead of an individual VPS.
4. Caddy on each backend continues to terminate TLS — or move TLS to the
   load balancer and run Caddy in HTTP-only mode (simpler cert lifecycle).

### Option B — Caddy upstream pool (self-managed)

If you already operate one VPS with Caddy and want to add capacity, the
single Caddy can `reverse_proxy` to multiple `app` containers running on
sibling VPSs. This trades the LB cost for a single-Caddy bottleneck — fine
up to a few thousand req/s.

### Rate-limit considerations

With N instances, the per-IP rate-limit headers reflect a single instance's
view, so the effective limit is `N × per_instance_limit`. The community
instance accepts this looseness ("best-effort"). Strict global limits
require a shared backend — Redis or Memorystore — which is in
[`TODO.md`](../TODO.md) under Backlog.

### Stateful gotchas

There are none today. If a future feature introduces shared state (e.g.
OIDC nonce/code-verifier tracking for the M4 provider surface), it must
land with a stateless storage option (signed cookie, JWT) or an explicit
external dependency, not local memory. This is a property of the
architecture worth defending — see `CLAUDE.md` § Stateless HTTP.
