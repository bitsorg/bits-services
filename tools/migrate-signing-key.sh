#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# A4 — one-time migration of the bits manifest-signing key into the running
# security-proxy. Converts a PEM Ed25519 private key to the proxy's raw-seed slot
# format and pushes it into the ingest slot, then verifies the loaded pubkey.
#
# YOU run this on the proxy host — it handles your private key. It is designed so
# the key never lands on disk or in shell history: the PEM is read once, converted
# in-memory, and piped straight into the proxy's ingest socket.
#
# Run from the bits-services checkout (where docker-compose.yml lives), with the
# security-proxy service up:
#
#   ./tools/migrate-signing-key.sh /secure/path/signing-key.pem [EXPECTED_KEYID16]
#
# EXPECTED_KEYID16 (optional): the 16-hex key_id bits ships as its trust anchor
# (from `bits`'s keys/*.pem). If given, the script asserts the loaded key matches
# and exits non-zero on mismatch.
#
# After success: take the offline backup (design §9a), then do A5 — set
# BITS_SECURITY_PROXY in CI to switch to the proxy path (the old --key path stays
# as a gated fallback). Delete BITS_SIGN_KEY only later, once the proxy path is
# proven in production.

set -euo pipefail

PEM="${1:?usage: migrate-signing-key.sh <signing-key.pem> [EXPECTED_KEYID16]}"
EXPECT="${2:-}"
SVC="${SECURITY_PROXY_SERVICE:-security-proxy}"     # docker compose service name
SLOT="${SIGN_KEY_SLOT:-bits-sign-key}"
ROUTE="${SIGN_ROUTE_SERVICE:-bits-manifest-sign}"   # route name in config.json
INGEST="/run/security-proxy/ingest.sock"
AGENT="/run/security-proxy/agent.sock"

[ -f "$PEM" ] || { echo "ERROR: no such PEM file: $PEM" >&2; exit 1; }

echo ">> converting PEM -> raw seed and pushing into slot '$SLOT' ..."
# The heredoc emits ONLY the base64 seed on stdout; it is piped directly into the
# proxy's push (no temp file). load_pem_private_key raises if it is not Ed25519.
python3 - "$PEM" <<'PY' | docker compose exec -T "$SVC" \
      security-proxy push "$SLOT" --socket "$INGEST"
import sys, base64
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
k = s.load_pem_private_key(open(sys.argv[1], "rb").read(), password=None)
if not isinstance(k, Ed25519PrivateKey):
    sys.exit("not an Ed25519 private key")
raw = k.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
sys.stdout.write(base64.b64encode(raw).decode())
PY

echo ">> verifying the loaded key via the sign route /pubkey ..."
TOKEN="$(docker compose exec -T "$SVC" security-proxy-token "$ROUTE" --socket "$AGENT")"
ADDR="$(docker compose exec -T "$SVC" security-proxy-token --addr --socket "$AGENT")"
KEYID_FULL="$(docker compose exec -T "$SVC" python3 - "$ADDR" "$TOKEN" <<'PY'
import sys, json, urllib.request
addr, token = sys.argv[1], sys.argv[2]
req = urllib.request.Request(addr + "/sign/bits/pubkey",
                             headers={"Authorization": "Bearer " + token})
print(json.load(urllib.request.urlopen(req))["keyid"])
PY
)"
KEYID16="${KEYID_FULL:0:16}"
echo "   loaded key_id (16) = $KEYID16"
echo "   loaded keyid (full) = $KEYID_FULL"

if [ -n "$EXPECT" ]; then
  if [ "$KEYID16" = "$EXPECT" ]; then
    echo ">> OK: loaded key matches expected trust anchor $EXPECT"
  else
    echo "ERROR: loaded key_id $KEYID16 != expected $EXPECT" >&2
    echo "       The wrong key is loaded. Do NOT proceed to A5." >&2
    exit 1
  fi
else
  echo ">> compare $KEYID16 against the key_id bits ships (keys/*.pem) before A5."
fi

echo ">> done. Next: offline backup (§9a), then A5 (set BITS_SECURITY_PROXY in CI;"
echo "   old --key path stays as fallback; delete BITS_SIGN_KEY later once proven)."
