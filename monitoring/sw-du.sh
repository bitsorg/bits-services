#!/bin/sh
# SPDX-FileCopyrightText: 2026 CERN
# SPDX-License-Identifier: GPL-3.0-or-later
#
# sw-du.sh — emit `bits_sw_dir_bytes`, the size of the bits sw/ build-products
# directory, for the Prometheus node-exporter *textfile* collector. The
# bits-console Monitoring tab shows the sum of this metric in the centre of the
# disk rings ("total sw"); vmagent adds the per-host `instance` label at scrape
# time, so this script emits the bare metric with no labels.
#
# Deploy on each BUILD HOST (the same node that runs node-exporter for the
# rings). Two moving parts:
#
#   1. node-exporter must be started with a textfile directory, e.g.
#        --collector.textfile.directory=/var/lib/node_exporter/textfile
#      (in the cvmfs-testbed compose that is the `node-exporter` service command;
#       on the runner fleet it is however that host runs node-exporter).
#
#   2. run THIS script periodically against that same directory — `du` can be
#      slow on a large tree, so every few minutes (not every scrape). Examples:
#        * cron:   */5 * * * *  BITS_SW_DIR=/container/bits/sw \
#                               TEXTFILE_DIR=/var/lib/node_exporter/textfile \
#                               /path/to/sw-du.sh
#        * systemd: a sw-du.service (Type=oneshot) driven by a sw-du.timer.
#
# Env:
#   BITS_SW_DIR    directory to measure   (default /container/bits/sw)
#   TEXTFILE_DIR   node-exporter textfile collector dir
#                                         (default /var/lib/node_exporter/textfile)
#
# The write is atomic (temp file + mv) so node-exporter never reads a partial
# file. Stdlib /bin/sh only; safe to bind-mount into a busybox sidecar.
set -eu

SW_DIR="${BITS_SW_DIR:-/container/bits/sw}"
TEXTFILE_DIR="${TEXTFILE_DIR:-/var/lib/node_exporter/textfile}"
out="${TEXTFILE_DIR}/bits_sw_dir.prom"

mkdir -p "${TEXTFILE_DIR}"

# du -sb reports apparent size in bytes; 0 if the dir is missing (fresh host).
bytes=$(du -sb "${SW_DIR}" 2>/dev/null | awk '{print $1; exit}')
[ -n "${bytes:-}" ] || bytes=0

tmp="$(mktemp "${TEXTFILE_DIR}/.bits_sw_dir.XXXXXX")"
{
  echo "# HELP bits_sw_dir_bytes Size in bytes of the bits sw/ build-products directory."
  echo "# TYPE bits_sw_dir_bytes gauge"
  echo "bits_sw_dir_bytes ${bytes}"
} > "${tmp}"
mv -f "${tmp}" "${out}"
