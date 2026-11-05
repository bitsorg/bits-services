#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Unlock the signing key into the RUNNING security-proxy: decrypt the passphrase-
# encrypted PEM (prompting for the passphrase) and push the raw seed into the
# in-memory slot. Run this on the proxy host after the container boots — and after
# any restart, since the slot is memory-only and does not survive a restart.
#
#   ./tools/unlock-signing-key.sh [secrets/bits-sign-key.enc.pem] [EXPECTED_KEYID16]
#
# The passphrase and the decrypted seed never touch disk or shell history: the
# passphrase is read from the terminal, decryption happens in memory, and the seed
# is piped straight into the proxy's ingest socket.

set -euo pipefail
# The steps are tools/unlocking.py's, which the host helper (bits-admin) reuses.
exec python3 "$(dirname "${BASH_SOURCE[0]}")/unlocking.py" unlock-signer "${1:-}" "${2:-}"
