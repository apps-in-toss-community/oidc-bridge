# Test fixtures

This directory contains **deliberately fake** test data:

- `test-mtls.cert.pem` / `test-mtls.key.pem` — self-signed RSA-2048
  cert+key used to assert that the Toss adapter wires PEMs into a
  `https.Agent`. Never used to talk to a real Toss host.
- `toss-*.json` — redacted snapshots of Toss `/generate-token` and
  `/login-me` SUCCESS and FAIL envelopes. PII fields are replaced
  with `"<redacted>"`.

These files are committed because they are not secrets.
