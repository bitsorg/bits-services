#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Unlock the signing key into the RUNNING security-proxy: decrypt the passphrase-
# encrypted PEM (prompting for the passphrase) and push the raw seed into the
# in-memory slot. Run this on the proxy host after the container boots — and after
# any restart, since the slot is memory-only and does not survive a restart.
#
#   ./tools/unlock-signing-key.sh [secrets/bits-sign-key.enc.pem] [EXPECTED_KEYID16]
#
# The passphrase and the decrypted seed never touch disk or shell history: the
# passphrase is read from the terminal, decryption happens in memory, and the seed
# is piped straight into the proxy's ingest socket.

set -euo pipefail

ENC="${1:-secrets/bits-sign-key.enc.pem}"
EXPECT="${2:-}"
SVC="${SECURITY_PROXY_SERVICE:-security-proxy}"
SLOT="${SIGN_KEY_SLOT:-bits-sign-key}"
ROUTE="${SIGN_ROUTE_SERVICE:-bits-manifest-sign}"
INGEST="/run/security-proxy/ingest.sock"
AGENT="/run/security-proxy/agent.sock"

[ -f "$ENC" ] || { echo "ERROR: no encrypted key at: $ENC (run encrypt-signing-key.sh first)" >&2; exit 1; }

echo ">> decrypting and pushing into slot '$SLOT' (you will be prompted for the passphrase) ..."
# getpass reads the passphrase from the controlling terminal, so stdout stays free
# to pipe the base64 seed into the proxy's push.
python3 - "$ENC" <<'PY' | docker compose exec -T "$SVC" security-proxy push "$SLOT" --socket "$INGEST"
import sys, base64, getpass
from cryptography.hazmat.primitives import serialization as s
p = getpass.getpass("Passphrase: ").encode()
try:
    k = s.load_pem_private_key(open(sys.argv[1], "rb").read(), password=p)
except (ValueError, TypeError):
    sys.exit("wrong passphrase, or not an encrypted Ed25519 key")
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

if [ -n "$EXPECT" ]; then
  [ "$KEYID16" = "$EXPECT" ] && echo ">> OK: matches expected trust anchor $EXPECT" \
    || { echo "ERROR: loaded key_id $KEYID16 != expected $EXPECT" >&2; exit 1; }
else
  echo ">> compare $KEYID16 against the key_id bits ships (keys/*.pem)."
fi
