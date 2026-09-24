#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# signing-check.sh — is signing live end to end? Inside the backend container,
# asks for the signing key the way /sign does (agent socket → proxy → loaded
# key), without the /trust/pubkey cache. Run by
# `make up` and `make status`. Exit 0 and print the key_id when it works; exit 1
# with a hint otherwise. The key lives only in proxy memory, so every proxy
# (re)start needs `make unlock`.
#
#   scripts/signing-check.sh [--wait SECONDS]   # wait for the backend to come up

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
WAIT=0
if [[ "${1:-}" == "--wait" ]]; then
  WAIT="${2:-30}"
  [[ "$WAIT" =~ ^[0-9]+$ ]] || { echo "usage: $0 [--wait SECONDS]" >&2; exit 2; }
fi

probe() {
  # Straight through the backend's own proxy client (agent socket -> proxy ->
  # loaded key), bypassing the 60 s /trust/pubkey cache, so "live" is current.
  docker compose exec -T bits-console-backend python3 - 2>/dev/null <<'PY'
try:
    from console_backend import config, signproxy
    from bits_helpers import trust
    print("OK " + signproxy.call(config.Settings(), trust.proxy_pubkey)[0])
except Exception as e:
    kind = "unconfigured " if type(e).__name__ == "Unavailable" else ""
    print("ERR %s%s" % (kind, e))
PY
}

deadline=$((SECONDS + WAIT))
while :; do
  R="$(probe)"
  [[ "$R" == OK* || $SECONDS -ge $deadline ]] && break
  # Keep waiting while the backend or the proxy's agent socket is still coming up.
  [[ -z "$R" || ( "$R" == *"agent socket"* && \
      ( "$R" == *"No such file"* || "$R" == *"Connection refused"* ) ) ]] || break
  sleep 3
done

case "$R" in
  OK*) echo "  signing         : live, key_id=${R#OK }"; exit 0 ;;
  "ERR unconfigured"*)
       echo "  signing         : not configured — ${R#ERR unconfigured }" ;;
  *"agent socket"*"Permission denied"*)
       echo "  signing         : backend may not read the proxy's agent socket — old socket"
       echo "                    layout? set agent_socket_group + ingest_socket in config.json"
       echo "                    (DEPLOYMENT.md, Upgrading)"
       echo "                    (${R#ERR })" ;;
  *"agent socket"*)
       echo "  signing         : proxy agent socket not answering (proxy down or starting? make up)"
       echo "                    (${R#ERR })" ;;
  ERR*)
       echo "  signing         : signing key NOT loaded (or proxy down) — run: make unlock"
       echo "                    (${R#ERR })" ;;
  *)   echo "  signing         : backend not answering (make up; make status)" ;;
esac
exit 1
