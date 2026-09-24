#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# functional-test.sh — run via `make test`. Non-interactive check that the
# server-side signing chain is wired: proxy up, backend serving https + healthz,
# and the backend can actually reach the sign-proxy. The browser-facing half (TLS
# trust + CORS) is verified separately in the console's Signing view → Backend
# diagnostics (only the browser can judge cert trust and cross-origin policy).

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
[[ -f .env ]] && { set -a; source .env; set +a; }   # generated, quoted → safe

PASS=0; FAIL=0
ok() { echo "  [ OK ] $*"; PASS=$((PASS+1)); }
no() { echo "  [FAIL] $*"; FAIL=$((FAIL+1)); }

echo "── bits-services functional test ──"

# 1. security-proxy up (agent socket present).
if docker compose exec -T security-proxy test -S /run/security-proxy/agent.sock 2>/dev/null; then
  ok "security-proxy agent socket present"
else
  no "security-proxy not up (make up), or key not unlocked (make unlock)"
fi

# 2. backend serves https and /healthz responds (self-signed → unverified context).
H="$(docker compose exec -T bits-console-backend python3 -c \
  "import ssl,urllib.request;print(urllib.request.urlopen('https://127.0.0.1:8443/healthz',context=ssl._create_unverified_context()).read().decode())" \
  2>/dev/null || true)"
if [[ -n "$H" ]]; then
  ok "backend /healthz responds over https"
  echo "$H" | grep -q '"webauthn_configured": *true'   && ok "backend WebAuthn configured"   || no "backend WebAuthn NOT configured (rp_id / origin / credentials)"
  echo "$H" | grep -q '"sign_proxy_configured": *true' && ok "backend sign-proxy configured" || no "backend sign-proxy not configured (BITS_SIGN_PROXY_AGENT_SOCKET)"
else
  no "backend /healthz not reachable (make up; check TLS_CERT_DIR cert/key)"
fi

# 3. backend reaches the loaded key (agent socket -> signer-net -> proxy -> key).
if S="$(bash "$DIR/scripts/signing-check.sh")"; then
  ok "backend reached the sign-proxy; ${S#*: }"
else
  no "backend could NOT sign: ${S#*: }"
fi

echo
echo "  ── $PASS passed, $FAIL failed ──"
if [[ $FAIL -eq 0 ]]; then
  echo "  Server side is wired. Finish in the browser:"
  echo "    open the console → Signing → Backend diagnostics (verifies TLS trust + CORS)."
else
  exit 1
fi
