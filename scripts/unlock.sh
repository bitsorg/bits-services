#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# unlock.sh — run via `make unlock`. Decrypts the signing key into the RUNNING
# security-proxy (prompts the passphrase) and then wires the backend's
# BITS_SIGN_PROXY_URL/TOKEN into .env. Both only exist once the proxy is up and
# change on every proxy restart, so re-run this after a restart.
#
#   make unlock                        # uses secrets/bits-sign-key.enc.pem
#   ./scripts/unlock.sh <enc.pem>      # explicit encrypted key
#   EXPECTED_KEYID16=<16hex> make unlock   # also assert the loaded key_id

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
ENC="${1:-secrets/bits-sign-key.enc.pem}"
ENV_FILE="$DIR/.env"
AGENT="/run/security-proxy/agent.sock"
ROUTE="bits-manifest-sign"

# 1. Decrypt + push the seed + verify the loaded key_id (interactive passphrase).
bash "$DIR/tools/unlock-signing-key.sh" "$ENC" "${EXPECTED_KEYID16:-}"

# 2. Read the live sign-route address + gate token from the running proxy.
echo ">> reading sign-route address + gate token from the proxy ..."
ADDR="$(docker compose exec -T security-proxy security-proxy-token --addr           --socket "$AGENT" | tr -d '\r')"
TOKEN="$(docker compose exec -T security-proxy security-proxy-token "$ROUTE" --socket "$AGENT" | tr -d '\r')"
PORT="$(printf '%s' "$ADDR" | sed -E 's#^https?://[^:]+:([0-9]+).*#\1#')"
[[ "$PORT" =~ ^[0-9]+$ ]] || { echo "ERROR: could not parse proxy port from '$ADDR'" >&2; exit 1; }
# The proxy binds a wildcard address; the backend reaches it by the docker service
# name + that port, not the advertised loopback host.
URL="http://security-proxy:${PORT}/sign/bits"

# 3. Update .env (replace the line if present, else append). '|' is a safe sed
#    delimiter here: proxy tokens are hex/base64url, the URL has none.
_set() {
  local k="$1" v="$2"
  touch "$ENV_FILE"
  if grep -q "^${k}=" "$ENV_FILE"; then
    sed -i.bak "s|^${k}=.*|${k}='${v}'|" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
  else
    echo "${k}='${v}'" >> "$ENV_FILE"
  fi
}
_set BITS_SIGN_PROXY_URL "$URL"
_set BITS_SIGN_PROXY_TOKEN "$TOKEN"

echo ">> wired BITS_SIGN_PROXY_URL=$URL into .env (token set; not printed)"
echo ">> recreate the backend to pick it up:  docker compose up -d bits-console-backend"
