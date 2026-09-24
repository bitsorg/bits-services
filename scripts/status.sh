#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# status.sh — run via `make status`. At-a-glance state of the bits-services stack:
# containers, the key .env config + cert presence, and health. If the backend is
# down it prints its last log lines so the cause is visible without a second step.

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
[[ -f .env ]] && { set -a; source .env; set +a; }   # generated, single-quoted → safe

echo "── containers ──"
docker compose ps 2>/dev/null || echo "  (docker compose not available / stack not created)"

echo
echo "── config (.env) ──"
if [[ -f .env ]]; then
  printf "  frontend origin : %s\n" "${BITS_FRONTEND_ORIGIN:-<unset>}"
  printf "  webauthn rp_id  : %s\n" "${BITS_WEBAUTHN_RP_ID:-<unset>}"
  printf "  admin policy    : %s\n" "${BITS_ADMINS_POLICY:-<unset>}"
  printf "  TLS cert dir    : %s" "${TLS_CERT_DIR:-<unset>}"
  if [[ -n "${TLS_CERT_DIR:-}" && -f "${TLS_CERT_DIR}/cert.pem" && -f "${TLS_CERT_DIR}/key.pem" ]]; then
    echo "   [cert.pem + key.pem present]"
  else
    echo "   [!! cert.pem/key.pem MISSING — backend will not start]"
  fi
  if [[ -n "${BITS_SIGN_PROXY_URL:-}${BITS_SIGN_PROXY_TOKEN:-}" ]]; then
    echo "  sign-proxy      : static BITS_SIGN_PROXY_URL/TOKEN in .env are obsolete (make unlock removes them)"
  fi
else
  echo "  no .env — run: make init"
fi

echo
echo "── health ──"
if docker compose exec -T security-proxy test -S /run/security-proxy/agent.sock 2>/dev/null; then
  echo "  security-proxy  : up (agent socket present)"
  G="$(docker compose exec -T security-proxy stat -c %G /run/security-proxy/agent.sock 2>/dev/null | tr -d '\r')"
  if [[ "$G" != "bitssign" ]] || \
     ! docker compose exec -T security-proxy test -S /run/security-proxy-ingest/ingest.sock 2>/dev/null; then
    echo "  security-proxy  : !! old socket layout (agent group '${G:-?}') — set agent_socket_group"
    echo "                    and ingest_socket in config.json (DEPLOYMENT.md, Upgrading)"
  fi
else
  echo "  security-proxy  : DOWN / no agent socket (make up)"
fi

H="$(docker compose exec -T bits-console-backend python3 -c \
  "import ssl,urllib.request;print(urllib.request.urlopen('https://127.0.0.1:8443/healthz',context=ssl._create_unverified_context()).read().decode())" \
  2>/dev/null || true)"
if [[ -n "$H" ]]; then
  echo "  backend         : up  $H"
else
  echo "  backend         : DOWN / not serving https:8443 — last log lines:"
  docker compose logs --tail=12 bits-console-backend 2>/dev/null | sed 's/^/      /' \
    || echo "      (no logs — is the container created? make build up)"
fi

bash "$DIR/scripts/signing-check.sh" || true
