#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# unlock.sh — run via `make unlock`. Decrypts the signing key into the RUNNING
# security-proxy (prompts the passphrase). The key lives only in proxy memory, so
# re-run this after every proxy (re)start. The backend finds the proxy's current
# port and gate token itself, via the shared agent socket — nothing to wire.
#
#   make unlock                        # uses secrets/bits-sign-key.enc.pem
#   ./scripts/unlock.sh <enc.pem>      # explicit encrypted key
#   EXPECTED_KEYID16=<16hex> make unlock   # also assert the loaded key_id

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
ENC="${1:-secrets/bits-sign-key.enc.pem}"
ENV_FILE="$DIR/.env"

# 1. Decrypt + push the seed + verify the loaded key_id (interactive passphrase).
bash "$DIR/tools/unlock-signing-key.sh" "$ENC" "${EXPECTED_KEYID16:-}"

# 2. Drop the static URL/token an older unlock wrote into .env: the backend now
#    reads them from the agent socket, and a stale copy only misleads.
if [[ -f "$ENV_FILE" ]] && grep -qE '^BITS_SIGN_PROXY_(URL|TOKEN)=' "$ENV_FILE"; then
  sed -i.bak -E '/^BITS_SIGN_PROXY_(URL|TOKEN)=/d' "$ENV_FILE" && rm -f "$ENV_FILE.bak"
  echo ">> removed the obsolete static BITS_SIGN_PROXY_URL/TOKEN from .env"
fi

# 3. End-to-end check through the backend.
bash "$DIR/scripts/signing-check.sh" --wait 15
