# SPDX-License-Identifier: Apache-2.0
# Sourced by the root install scripts (helper-install.sh, admin-install.sh).

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

# ensure_user NAME UID GROUP: a system account (no login, no home) when missing; one
# that exists must have UID.
ensure_user() {
  local name="$1" uid="$2" group="$3" entry
  if entry="$(getent passwd "$name")"; then
    [[ "$(cut -d: -f3 <<<"$entry")" == "$uid" ]] || {
      echo "user $name exists with uid $(cut -d: -f3 <<<"$entry"), not $uid" >&2; exit 1; }
    echo "user $name ($uid) is there"
  elif entry="$(getent passwd "$uid")"; then
    echo "uid $uid belongs to user $(cut -d: -f1 <<<"$entry"), not $name" >&2; exit 1
  else
    useradd --system --uid "$uid" --gid "$group" --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin "$name"
    echo "created user $name ($uid)"
  fi
}
