#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# admin-install.sh — run as root (sudo make admin-install): the bits-admin group (the
# admins) and system user (the container), 10003, when missing, /run/bits-admin for
# its socket and setup code, now and at every boot (tmpfiles.d), and admin-data/ for
# its passkeys. Safe to rerun.

set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$DIR"
TMPFILES="${TMPFILES_DIR:-/etc/tmpfiles.d}/bits-admin.conf"
RUN_DIR="${ADMIN_RUN_DIR:-/run/bits-admin}"

[[ "$(id -u)" == 0 ]] || { echo "run as root: sudo make admin-install" >&2; exit 1; }
source "$DIR/scripts/lib-host.sh"
ensure_group bits-admin 10003
ensure_user bits-admin 10003 bits-admin

# 0750, the container's user: admins (the group) open the socket and read the code,
# and cannot put anything else there.
tmp="$(mktemp "$(dirname "$TMPFILES")/.bits-admin.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
echo "d $RUN_DIR 0750 bits-admin bits-admin -" > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$TMPFILES"
systemd-tmpfiles --create "$TMPFILES"
[[ "$(stat -c '%a %U:%G' "$RUN_DIR")" == "750 bits-admin:bits-admin" ]] || {
  echo "$RUN_DIR is $(stat -c '%a %U:%G' "$RUN_DIR"), not 750 bits-admin:bits-admin" >&2; exit 1; }

# The passkeys and the encrypted passphrases (never a passphrase): the container's only.
# chown/chmod act on the directory entered, so a symlink swapped in cannot redirect them.
mkdir -p admin-data
cd admin-data
[[ "$(pwd -P)" == "$DIR/admin-data" ]] || { echo "admin-data is not a plain directory; refusing" >&2; exit 1; }
chown bits-admin:bits-admin .
chmod 0700 .
cd "$DIR"
echo "$RUN_DIR and $DIR/admin-data ready. Admins: usermod -aG bits-admin <user> (then log in again);"
echo "tunnel: ssh -N -o ExitOnForwardFailure=yes -L 127.0.0.1:8800:$RUN_DIR/admin.sock <this host>"
echo "then open http://bits-admin.localhost:8800 (make admin-code prints the sign-in code)"
