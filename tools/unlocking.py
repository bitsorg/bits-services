#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""unlocking.py — what `make unlock` does, as functions the host helper reuses.

    tools/unlocking.py unlock-signer [secrets/bits-sign-key.enc.pem] [EXPECTED_KEYID16]

decrypts the signing key on the host (the passphrase read from the terminal) and
pushes the raw seed into the running security proxy's ingest socket, then reads
the loaded key's id back through its sign route. Nothing touches disk.
"""

import base64
import datetime
import getpass
import json
import os
import subprocess
import sys

DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INGEST = "/run/security-proxy-ingest/ingest.sock"
AGENT = "/run/security-proxy/agent.sock"
SIGNER = os.environ.get("SECURITY_PROXY_SERVICE", "security-proxy")
SIGN_SLOT = os.environ.get("SIGN_KEY_SLOT", "bits-sign-key")
SIGN_ROUTE = os.environ.get("SIGN_ROUTE_SERVICE", "bits-manifest-sign")
SECRETS_FILE = os.environ.get("SERVICE_SECRETS", os.path.join(DIR, "secrets", "service-secrets.enc"))
CRED_PROXY = os.environ.get("CREDENTIALS_PROXY_SERVICE", "credentials-proxy")
# The store writer (M8a): the store's keypair goes there, out of the backend's reach.
WRITER = os.environ.get("STORE_WRITER_SERVICE", "store-writer")
CERT_SLOT = "client-cert"
# Run inside the signer's container: the gate token never leaves it (no argv on the host).
PUBKEY = r'''
import sys, json, subprocess, urllib.request
route, agent = sys.argv[1], sys.argv[2]
token = subprocess.check_output(["security-proxy-token", route, "--socket", agent], text=True).strip()
addr = subprocess.check_output(["security-proxy-token", "--addr", "--socket", agent], text=True).strip()
req = urllib.request.Request(addr + "/sign/bits/pubkey", headers={"Authorization": "Bearer " + token})
print(json.load(urllib.request.urlopen(req))["keyid"])
'''


class UnlockError(Exception):
    """A step failed; the message names it, never a passphrase or a secret."""


def _compose(args, value=None):
    try:
        r = subprocess.run(["docker", "compose"] + args, cwd=DIR, capture_output=True,
                           input=value.encode() if value is not None else None)
    except FileNotFoundError:
        raise UnlockError("docker is not installed or not on PATH")
    return r.returncode, r.stdout.decode(), r.stderr.decode()


def decrypt_signing_seed(enc_path, passphrase):
    """The raw Ed25519 seed of the encrypted PEM, base64."""
    from cryptography.hazmat.primitives import serialization as s
    with open(enc_path, "rb") as f:
        pem = f.read()
    try:
        key = s.load_pem_private_key(pem, password=passphrase)
        raw = key.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    except (ValueError, TypeError):
        raise UnlockError("wrong passphrase, or not an encrypted Ed25519 key")
    return base64.b64encode(raw).decode()


def push(slot, value, service):
    """Pushes a value into a proxy's in-memory slot; returns what the proxy said."""
    code, out, err = _compose(["exec", "-T", service, "security-proxy", "push", slot,
                               "--socket", INGEST], value)
    if code:
        raise UnlockError("push %s into %s failed: %s" % (slot, service, (err or out).strip()[:300]))
    return out


def signing_key_id(service=SIGNER, route=SIGN_ROUTE):
    """The full key id the signer has loaded, read through its sign route."""
    code, keyid, err = _compose(["exec", "-T", service, "python3", "-", route, AGENT], PUBKEY)
    if code:
        raise UnlockError("the sign route did not answer: %s" % err.strip()[-300:])
    return keyid.strip()


def unlock_signer(passphrase, enc_path=os.path.join(DIR, "secrets", "bits-sign-key.enc.pem")):
    """Decrypts and pushes the signing key; returns (what the proxy said, key id)."""
    said = push(SIGN_SLOT, decrypt_signing_seed(enc_path, passphrase), SIGNER)
    return said, signing_key_id()


def _scrypt(passphrase, salt, n=2 ** 15, r=8, p=1):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase)


def load_service_secrets(passphrase, path=SECRETS_FILE):
    """The service secrets ({slot: value}); {} when there is no file yet."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if not os.path.exists(path):
        return {}
    with open(path) as f:
        box = json.load(f)
    salt, nonce = base64.b64decode(box["salt"]), base64.b64decode(box["nonce"])
    try:
        plain = AESGCM(_scrypt(passphrase, salt, box["n"], box["r"], box["p"])).decrypt(
            nonce, base64.b64decode(box["ct"]), b"service-secrets/1")
    except Exception:
        raise UnlockError("wrong passphrase, or %s is damaged" % path)
    return json.loads(plain)


def _throwaway_cert():
    """A self-signed client certificate for the proxy's TLS client: required by
    the proxy, asked for by none of these upstreams, never written to disk."""
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "bits credentials proxy")])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(days=1))
            .not_valid_after(now + datetime.timedelta(days=3650))
            .sign(key, hashes.SHA256()))
    return (cert.public_bytes(serialization.Encoding.PEM)
            + key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                serialization.NoEncryption())).decode()


def running(service):
    code, out, _ = _compose(["ps", "-q", "--status", "running", service])
    return code == 0 and bool(out.strip())


def _env_file():
    out = {}
    path = os.path.join(DIR, ".env")
    if os.path.exists(path):
        for line in open(path):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip("'\"")
    return out


def _writer_configured():
    """True when the store writer has a config: then s3-* slots must go there, not quietly
    into the credentials proxy."""
    d = os.environ.get("STORE_WRITER_CONFIG_DIR") or _env_file().get("STORE_WRITER_CONFIG_DIR") \
        or "./config/store-writer"
    return os.path.isfile(os.path.join(DIR, d, "config.json"))


def push_service_secrets(secrets):
    """Pushes the service secrets into the running proxies; returns {service: [slots]}."""
    if not secrets:
        raise UnlockError("no service secrets yet (tools/service-secrets.py set <slot>)")
    # (A new client certificate makes the proxy rebuild its HTTPS client:
    # requests in flight through it are cut, and retried by the services.)
    writer = running(WRITER)
    if not writer and _writer_configured() and any(k.startswith("s3-") for k in secrets):
        raise UnlockError("%s is configured but not running: start it first"
                          " (docker compose --profile store up -d %s), then push again"
                          % (WRITER, WRITER))
    for service in (CRED_PROXY, WRITER) if writer else (CRED_PROXY,):
        out = push(CERT_SLOT, _throwaway_cert(), service)
        if "tls: ready" not in out:
            raise UnlockError("%s did not take the client certificate: %s" % (service, out.strip()))
    where = {}
    for slot in sorted(secrets):
        service = (WRITER if writer and (slot.startswith("s3-") or slot == "gitlab-mirror")
                   else CRED_PROXY)
        push(slot, secrets[slot], service)
        where.setdefault(service, []).append(slot)
    return where


def main(argv):
    if not argv or argv[0] != "unlock-signer":
        sys.exit(__doc__.split("\n\n")[1])
    enc = argv[1] if len(argv) > 1 and argv[1] else "secrets/bits-sign-key.enc.pem"
    expect = argv[2] if len(argv) > 2 else ""
    if not os.path.isfile(enc):
        sys.exit("ERROR: no encrypted key at: %s (run encrypt-signing-key.sh first)" % enc)
    print(">> decrypting and pushing into slot '%s' (you will be prompted for the passphrase) ..."
          % SIGN_SLOT, flush=True)
    try:
        seed = decrypt_signing_seed(enc, getpass.getpass("Passphrase: ").encode())
        sys.stdout.write(push(SIGN_SLOT, seed, SIGNER))
        print(">> verifying the loaded key via the sign route /pubkey ...", flush=True)
        keyid16 = signing_key_id()[:16]
    except UnlockError as e:
        sys.exit(str(e))
    print("   loaded key_id (16) = %s" % keyid16)
    if expect and keyid16 != expect:
        sys.exit("ERROR: loaded key_id %s != expected %s" % (keyid16, expect))
    print(">> OK: matches expected trust anchor %s" % expect if expect
          else ">> compare %s against the key_id bits ships (keys/*.pem)." % keyid16)


if __name__ == "__main__":
    main(sys.argv[1:])
