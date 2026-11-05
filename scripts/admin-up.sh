#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# admin-up.sh — start bits-admin and wait until it answers /healthz on its socket.
# The probe runs inside the container: a socket file left by a stopped run
# exists but refuses connections, so only a live listener counts.

set -uo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$DIR"
COMPOSE="${COMPOSE:-docker compose}"
RUN_DIR="${ADMIN_RUN_DIR:-/run/bits-admin}"
TRIES="${ADMIN_WAIT_TRIES:-15}"
ERR="$(mktemp)"
trap 'rm -f "$ERR"' EXIT

for d in "$RUN_DIR" admin-data; do
  [[ "$(stat -c %U:%G "$d" 2>/dev/null)" == bits-admin:bits-admin ]] \
    || { echo "first: sudo make admin-install" >&2; exit 1; }
done
$COMPOSE --profile admin up -d bits-admin || exit 1

for ((i = 0; i < TRIES; i++)); do
  $COMPOSE --profile admin exec -T bits-admin python3 - 2>"$ERR" <<'PY' && { echo "bits-admin is up"; exit 0; }
import http.client, os, socket
c = http.client.HTTPConnection("localhost", timeout=2)
c.sock = socket.socket(socket.AF_UNIX)
c.sock.settimeout(2)
c.sock.connect(os.environ["BITS_ADMIN_SOCKET"])
c.request("GET", "/healthz")
raise SystemExit(c.getresponse().status != 200)
PY
  sleep 1
done
echo "bits-admin did not answer on its socket; the last probe said:" >&2
tail -3 "$ERR" >&2
echo "its last log lines:" >&2
$COMPOSE --profile admin logs --tail 20 bits-admin >&2
exit 1
