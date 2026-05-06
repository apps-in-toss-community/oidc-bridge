#!/usr/bin/env bash
# scripts/smoke-image.sh — runs the bridge image against SQLite + mock Toss
# adapter and asserts /healthz, /status, and `bridge doctor` all respond
# correctly.
#
# Inputs (env, all optional):
#   IMAGE         default: bridge:dev
#   PORT          default: 18080  (host port; container always uses 8080)
#
# Outputs: exit 0 on green or yellow doctor result, non-zero on red or any
# failure. Logs go to stderr; only the `[smoke] PASS:` / `[smoke] OK` lines
# go to stdout for easy scripting.
#
# What it exercises:
#   - Image entrypoint (dumb-init) and CMD start node correctly.
#   - HEALTHCHECK reports healthy within 60 s.
#   - /healthz returns {"status":"ok"} (Phase 0 contract).
#   - /status?format=json returns 200 with a parseable {status,items} body
#     (Phase 8 contract).
#   - The CLI inside the container can run doctor --json and the result is
#     green or yellow (yellow is acceptable here because no Toss cert is
#     provided to this smoke).
set -euo pipefail

IMAGE="${IMAGE:-bridge:dev}"
PORT="${PORT:-18080}"
CONTAINER="bridge-smoke-$$"
WORK="$(mktemp -d -t bridge-smoke-XXXXXX)"

cleanup() {
  docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT

# Generate a throwaway RS256 signing key so the bridge can boot and sign
# id_tokens. The key never leaves $WORK and is discarded on cleanup.
openssl genrsa -out "$WORK/k1.pem" 2048 2>/dev/null
SIGNING_PEM="$(cat "$WORK/k1.pem")"

# Generate a 32-byte master key in hex for the env provider.
MASTER_KEY_1_HEX="$(head -c 32 /dev/urandom | xxd -p -c 64)"

echo "[smoke] starting $IMAGE on host port $PORT" >&2

docker run --rm --name "$CONTAINER" -d \
  -p "127.0.0.1:${PORT}:8080" \
  -e OIDC_ISSUER="http://localhost:${PORT}" \
  -e OIDC_ACTIVE_KID=k1 \
  -e "OIDC_SIGNING_KEY_K1_PEM=${SIGNING_PEM}" \
  -e BRIDGE_TOSS_ADAPTER=mock \
  -e MASTER_KEY_PROVIDER=env \
  -e "MASTER_KEY_1_HEX=${MASTER_KEY_1_HEX}" \
  -e STORAGE=sqlite \
  -e SQLITE_PATH=/app/data/bridge.db \
  "$IMAGE" >/dev/null

# Wait up to 60 s for healthcheck to flip green. start_period is 15 s in the
# Dockerfile so we expect first probe around T+15 s with healthy by T+25 s.
for _ in $(seq 1 60); do
  state="$(docker inspect --format='{{.State.Health.Status}}' "$CONTAINER" 2>/dev/null || echo none)"
  if [ "$state" = "healthy" ]; then break; fi
  sleep 1
done
if [ "${state:-none}" != "healthy" ]; then
  echo "[smoke] FAIL: container did not become healthy in 60 s (state=${state:-none})" >&2
  docker logs "$CONTAINER" 2>&1 | tail -50 >&2
  exit 1
fi
echo "[smoke] container healthy" >&2

# /healthz must return {"status":"ok"} (Phase 0 contract).
got="$(curl -fsS "http://127.0.0.1:${PORT}/healthz")"
case "$got" in
  *'"status":"ok"'*) ;;
  *)
    echo "[smoke] FAIL: /healthz returned '$got' (want JSON with status:ok)" >&2
    exit 1 ;;
esac
echo "[smoke] /healthz ok" >&2

# /status?format=json must return HTTP 200 with a parseable {status,items} body.
status_code="$(curl -s -o "$WORK/status.json" -w '%{http_code}' "http://127.0.0.1:${PORT}/status?format=json")"
if [ "$status_code" != "200" ]; then
  echo "[smoke] FAIL: /status returned HTTP $status_code" >&2
  cat "$WORK/status.json" >&2
  exit 1
fi
status_field="$(node -e 'const s=require("fs").readFileSync(0,"utf8"); const o=JSON.parse(s); if(!o||typeof o.status!=="string"||!Array.isArray(o.items)){process.stderr.write("invalid /status shape\n");process.exit(1)} process.stdout.write(o.status)' < "$WORK/status.json")"
echo "[smoke] /status: status=$status_field" >&2

# Run `oidc-bridge doctor --json` inside the container and parse it via the
# shared scripts/lib/parse-doctor.ts helper (the same parser the vitest suite
# pins). Yellow is acceptable here because no Toss cert is provided.
doctor_out="$(docker exec "$CONTAINER" node dist/index.mjs doctor --json 2>/dev/null || true)"
if [ -z "$doctor_out" ]; then
  echo "[smoke] FAIL: doctor command produced no output" >&2
  exit 1
fi

# Parse via tsx so we use the canonical helper. node --experimental-strip-types
# would also work on Node 24 but tsx is the project's existing runner.
state_out="$(printf '%s' "$doctor_out" | node --experimental-strip-types -e '
  let buf = ""; process.stdin.on("data", c => buf += c); process.stdin.on("end", async () => {
    const { extractDoctorState } = await import("./scripts/lib/parse-doctor.ts");
    try { process.stdout.write(extractDoctorState(buf)); }
    catch (e) { process.stderr.write(String((e instanceof Error ? e.message : e))); process.exit(2); }
  });
')"

case "$state_out" in
  green|yellow)
    echo "[smoke] PASS: doctor=$state_out"
    echo "[smoke] OK"
    exit 0 ;;
  red)
    echo "[smoke] FAIL: doctor=red" >&2
    printf '%s\n' "$doctor_out" >&2
    exit 1 ;;
  *)
    echo "[smoke] FAIL: doctor returned unexpected state '$state_out'" >&2
    printf '%s\n' "$doctor_out" >&2
    exit 1 ;;
esac
