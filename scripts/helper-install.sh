#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# helper-install.sh — run as root (sudo make helper-install): creates the helper's
# group when missing (an existing one must have the expected gid), installs the
# systemd unit for this checkout and (re)starts it. Safe to run again.

set -euo pipefail
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$DIR"
# The path goes into the unit (sed, systemd): plain characters only.
[[ "$DIR" =~ ^/[A-Za-z0-9._/-]+$ ]] || { echo "unsupported checkout path: $DIR" >&2; exit 1; }
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
UNIT="$UNIT_DIR/bits-admin-helper.service"

[[ "$(id -u)" == 0 ]] || { echo "run as root: sudo make helper-install" >&2; exit 1; }

# ensure_group NAME GID: created when missing; one that exists must have GID.
ensure_group() {
  local name="$1" gid="$2" entry
  if entry="$(getent group "$name")"; then
    [[ "$(cut -d: -f3 <<<"$entry")" == "$gid" ]] || {
      echo "group $name exists with gid $(cut -d: -f3 <<<"$entry"), not $gid" >&2; exit 1; }
    echo "group $name ($gid) is there"
  elif entry="$(getent group "$gid")"; then
    echo "gid $gid belongs to group $(cut -d: -f1 <<<"$entry"), not $name" >&2; exit 1
  else
    groupadd --system --gid "$gid" "$name"
    echo "created group $name ($gid)"
  fi
}

[[ "$(systemctl is-enabled bits-admin-helper 2>/dev/null || true)" != masked ]] || {
  echo "bits-admin-helper is masked: systemctl unmask it first" >&2; exit 1; }
[[ -f tools/bits-admin-helper.service ]] || { echo "no tools/bits-admin-helper.service here" >&2; exit 1; }
ensure_group bits-admin-helper 10004
if [[ -f "$UNIT" ]]; then
  old="$(sed -n 's/^Description=.* for //p' "$UNIT")"
  [[ "$old" == "$DIR" ]] || echo "replacing the unit installed for: ${old:-unknown}"
fi
tmp="$(mktemp "$UNIT_DIR/.bits-admin-helper.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
sed "s|@DIR@|$DIR|g" tools/bits-admin-helper.service > "$tmp"
chmod 0644 "$tmp"
mv -f "$tmp" "$UNIT"
systemctl daemon-reload
systemctl restart bits-admin-helper
sleep 1  # the helper checks its group as it starts
if ! systemctl is-active --quiet bits-admin-helper; then
  systemctl --no-pager --lines=10 status bits-admin-helper || true
  exit 1
fi
echo "bits-admin-helper running for $DIR (at boot too: systemctl enable bits-admin-helper)"
