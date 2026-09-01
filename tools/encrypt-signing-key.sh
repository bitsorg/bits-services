#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# One-time: turn a passphrase-LESS Ed25519 signing key (PEM) into a passphrase-
# ENCRYPTED PEM, for use with unlock-signing-key.sh. Prompts for a new passphrase
# (never on argv); writes the encrypted key to secrets/ (gitignored).
#
#   ./tools/encrypt-signing-key.sh /secure/path/signing-key.pem
#
# After this succeeds:
#   * keep the passphrase in your password manager — NOT on disk;
#   * securely delete the plaintext key:  shred -u <plaintext.pem>   (macOS: rm -P)
#   * keep an OFFLINE backup of the plaintext key (design §9a) somewhere safe,
#     e.g. printed in a safe — the encrypted blob + passphrase is your online copy.

set -euo pipefail

IN="${1:?usage: encrypt-signing-key.sh <plaintext-key.pem> [OUT]}"
OUT="${2:-secrets/bits-sign-key.enc.pem}"
[ -f "$IN" ] || { echo "ERROR: no such file: $IN" >&2; exit 1; }
mkdir -p "$(dirname "$OUT")"

python3 - "$IN" "$OUT" <<'PY'
import sys, getpass
from cryptography.hazmat.primitives import serialization as s
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
try:
    k = s.load_pem_private_key(open(sys.argv[1], "rb").read(), password=None)
except TypeError:
    sys.exit("that PEM is already encrypted — nothing to do")
if not isinstance(k, Ed25519PrivateKey):
    sys.exit("not an Ed25519 private key")
p1 = getpass.getpass("New passphrase: ").encode()
if len(p1) < 8:
    sys.exit("passphrase too short (use >= 8 chars, ideally a long passphrase)")
if p1 != getpass.getpass("Confirm passphrase: ").encode():
    sys.exit("passphrases do not match")
enc = k.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8,
                      s.BestAvailableEncryption(p1))
open(sys.argv[2], "wb").write(enc)
print("wrote encrypted key ->", sys.argv[2])
PY

chmod 600 "$OUT"
echo ">> done. Passphrase -> your password manager. Then securely delete the plaintext:"
echo "     shred -u \"$IN\"      # (macOS: rm -P \"$IN\")"
