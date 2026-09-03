#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# setup.sh — one-time bits-services installer (run via `make init`). Modeled on
# cvmfs-testbed's init.sh. Idempotent: loads any existing .env and reuses its
# values, generates missing keys (a self-signed backend TLS cert), copies the
# security-proxy config, optionally encrypts your signing key, and writes .env.
#
# Sensible defaults assume the GitLab Pages frontend bits-console.web.cern.ch.
# WebAuthn rp_id/origin and the CORS origin are DERIVED from the frontend origin.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"

BLUE='\033[0;34m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC}  $*"; }
success() { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }

ENV_FILE="$DIR/.env"

# Load existing .env so a re-run reuses previously entered values. The file is
# machine-generated with quoted values, so sourcing is safe.
if [[ -f "$ENV_FILE" ]]; then
  info "Loading existing .env — press Enter to keep each shown value."
  set -a; # shellcheck disable=SC1090
  source "$ENV_FILE"; set +a
fi

# _ask VAR "label" "default": prompt, defaulting to the current value (from .env)
# then the given default.
_ask() {
  local __var="$1" __label="$2" __def="${3:-}" __cur="${!1:-}" __in
  local __d="${__cur:-$__def}"
  read -rp "$__label [${__d}]: " __in
  printf -v "$__var" '%s' "${__in:-$__d}"
}

echo "=== bits-services setup ==="

# ── Prompts ───────────────────────────────────────────────────────────────────
_ask GITLAB_API_URL          "GitLab API URL"                     "https://gitlab.cern.ch/api/v4"
_ask FRONTEND_ORIGIN         "Frontend origin (GitLab Pages)"     "https://bits-console.web.cern.ch"
_ask BACKEND_HOST            "Backend host (TLS cert CN/SAN)"     "bits.cern.ch"
_gituser="$(git config user.email 2>/dev/null | sed 's/@.*//' || true)"; : "${_gituser:=youruser}"
echo "  (admin policy uses your GITLAB username — may differ from your login '${_gituser}')"
_ask BITS_ADMINS_POLICY      "Admin policy: * @<gitlab-username>"  "* @${_gituser}"
_ask SECURITY_PROXY_CONFIG_DIR "Security-proxy config dir"        "$DIR/config/security-proxy"
_ask TLS_CERT_DIR            "Backend TLS cert dir"               "$DIR/secrets/tls"
_ask BITS_SRC                "Local bits checkout"                "../bits"

# ── Derive WebAuthn + CORS from the frontend origin ───────────────────────────
BITS_FRONTEND_ORIGIN="$FRONTEND_ORIGIN"
BITS_WEBAUTHN_ORIGIN="$FRONTEND_ORIGIN"
BITS_WEBAUTHN_RP_ID="$(printf '%s' "$FRONTEND_ORIGIN" | sed -E 's#^https?://([^/:]+).*#\1#')"

# ── Security-proxy config ─────────────────────────────────────────────────────
install -d "$SECURITY_PROXY_CONFIG_DIR"
if [[ ! -f "$SECURITY_PROXY_CONFIG_DIR/config.json" ]]; then
  cp "$DIR/security-proxy/config.sample.json" "$SECURITY_PROXY_CONFIG_DIR/config.json"
  success "copied config.sample.json -> $SECURITY_PROXY_CONFIG_DIR/config.json"
else
  info "proxy config.json already present"
fi

# ── Backend TLS cert (generate a self-signed pair if missing) ─────────────────
install -d "$TLS_CERT_DIR"
if [[ -f "$TLS_CERT_DIR/cert.pem" && -f "$TLS_CERT_DIR/key.pem" ]]; then
  info "TLS cert already present in $TLS_CERT_DIR"
elif command -v openssl >/dev/null 2>&1; then
  info "generating a self-signed TLS cert for $BACKEND_HOST"
  # In an `if` so a failure (e.g. LibreSSL lacking -addext) is non-fatal.
  if openssl req -x509 -newkey rsa:2048 -nodes -days 825 \
       -keyout "$TLS_CERT_DIR/key.pem" -out "$TLS_CERT_DIR/cert.pem" \
       -subj "/CN=$BACKEND_HOST" -addext "subjectAltName=DNS:$BACKEND_HOST" >/dev/null 2>&1; then
    chmod 644 "$TLS_CERT_DIR/cert.pem"   # public cert
    chmod 600 "$TLS_CERT_DIR/key.pem"
    # The backend container runs as `nobody` (uid 65534), a different uid than the
    # host owner, so it can't read a 600 key the host user owns. Prefer to chown the
    # key to 65534 (needs sudo) so ONLY the backend user + root can read it — keeping
    # it non-world-readable. Fall back to a world-readable key (0644) for a
    # self-signed TEST cert if sudo/chown isn't available.
    if sudo chown 65534:65534 "$TLS_CERT_DIR/key.pem"; then
      success "wrote $TLS_CERT_DIR/{cert,key}.pem (key owned by backend user 65534, mode 600)"
    else
      chmod 644 "$TLS_CERT_DIR/key.pem"
      warn "no sudo/chown — key.pem left world-readable (0644); OK for a self-signed test cert."
    fi
    warn "self-signed: fine when a CERN front RE-ENCRYPTS to the backend."
    warn "if the browser reaches the backend directly, replace with a browser-trusted cert."
  else
    rm -f "$TLS_CERT_DIR/key.pem" "$TLS_CERT_DIR/cert.pem"
    warn "openssl could not generate the cert (needs OpenSSL >= 1.1.1 for -addext)."
    warn "provide $TLS_CERT_DIR/cert.pem + key.pem yourself, then re-run make init."
  fi
else
  warn "openssl not found — provide $TLS_CERT_DIR/cert.pem + key.pem yourself."
fi

# ── Signing key: offer to encrypt if the encrypted blob is missing ────────────
if [[ -f "$DIR/secrets/bits-sign-key.enc.pem" ]]; then
  info "encrypted signing key already present (secrets/bits-sign-key.enc.pem)"
else
  read -rp "Encrypt your Ed25519 signing key now? path to key PEM (blank to skip): " _keypem
  [[ -n "${_keypem:-}" ]] && bash "$DIR/tools/encrypt-signing-key.sh" "$_keypem"
fi

# ── Write .env ────────────────────────────────────────────────────────────────
# Single-quoted values are literal for BOTH bash `source` and docker compose (no
# $ / backtick expansion in either), so a free-text admin policy can't be mangled
# or execute anything on the next re-source. (Values must not contain a literal
# single quote — none of these fields legitimately do.)
{
  echo "# generated by scripts/setup.sh on $(date -u '+%Y-%m-%dT%H:%M:%SZ') — re-run: make init"
  echo "SECURITY_PROXY_CONFIG_DIR='${SECURITY_PROXY_CONFIG_DIR}'"
  echo "BITS_SRC='${BITS_SRC}'"
  echo "TLS_CERT_DIR='${TLS_CERT_DIR}'"
  echo "BITS_SIGN_PROXY_URL='${BITS_SIGN_PROXY_URL:-}'"
  echo "BITS_SIGN_PROXY_TOKEN='${BITS_SIGN_PROXY_TOKEN:-}'"
  echo "GITLAB_API_URL='${GITLAB_API_URL}'"
  echo "BITS_FRONTEND_ORIGIN='${BITS_FRONTEND_ORIGIN}'"
  echo "BITS_ADMINS_POLICY='${BITS_ADMINS_POLICY}'"
  echo "BITS_ADMIN_RESOLVE_TOKEN='${BITS_ADMIN_RESOLVE_TOKEN:-}'"
  echo "BITS_WEBAUTHN_RP_ID='${BITS_WEBAUTHN_RP_ID}'"
  echo "BITS_WEBAUTHN_ORIGIN='${BITS_WEBAUTHN_ORIGIN}'"
  echo "BITS_WEBAUTHN_CREDENTIALS='${BITS_WEBAUTHN_CREDENTIALS:-/data/creds.json}'"
  echo "BITS_WEBAUTHN_REQUIRE_UV='${BITS_WEBAUTHN_REQUIRE_UV:-1}'"
  echo "BITS_ENROLLMENT_AUTHORITY='${BITS_ENROLLMENT_AUTHORITY:-1}'"
  echo "BITS_WEBAUTHN_REQUIRED='${BITS_WEBAUTHN_REQUIRED:-0}'"
  echo "BITS_OIDC_ISSUER='${BITS_OIDC_ISSUER:-}'"
  echo "BITS_OIDC_CI_AUDIENCE='${BITS_OIDC_CI_AUDIENCE:-}'"
  echo "BITS_OIDC_JWKS_URL='${BITS_OIDC_JWKS_URL:-}'"
  echo "BITS_CI_SIGNERS='${BITS_CI_SIGNERS:-}'"
} > "$ENV_FILE"
chmod 600 "$ENV_FILE"

success "wrote $ENV_FILE"
echo
echo "Next steps:"
echo "  make build up      # build images and start the proxy + backend"
echo "  make unlock        # decrypt the key into the proxy + wire its URL/token into .env"
echo "  make test          # functional wiring check"
echo "Then finish in the browser: open the console's Signing view → Backend diagnostics."
