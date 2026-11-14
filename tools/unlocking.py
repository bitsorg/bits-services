#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""unlocking.py — what `make unlock` does, as functions the host helper reuses.

    tools/unlocking.py unlock-signer [secrets/bits-sign-key.enc.pem] [EXPECTED_KEYID16]
    tools/unlocking.py store-token-key
    tools/unlocking.py store-build-token-key

decrypts the signing key on the host (the passphrase read from the terminal) and
pushes the raw seed into the running security proxy's ingest socket, then reads
the loaded key's id back through its sign route. Nothing touches disk. The store
tokens' keys (store-token-key, store-build-token-key: made once, same passphrase)
go in with it.
"""

import base64
import contextlib
import datetime
import getpass
import json
import os
import subprocess
import sys
import tempfile

DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INGEST = "/run/security-proxy-ingest/ingest.sock"
AGENT = "/run/security-proxy/agent.sock"
SIGNER = os.environ.get("SECURITY_PROXY_SERVICE", "security-proxy")
SIGN_SLOT = os.environ.get("SIGN_KEY_SLOT", "bits-sign-key")
SIGN_ROUTE = os.environ.get("SIGN_ROUTE_SERVICE", "bits-manifest-sign")
SIGN_KEY = os.path.join(DIR, "secrets", "bits-sign-key.enc.pem")
# The store tokens' key: in a proxy of its own, which the backend reaches (M8b).
STORE_SIGNER = os.environ.get("STORE_TOKEN_SIGNER_SERVICE", "store-token-signer")
STORE_SLOT = "bits-store-token-key"
STORE_KEY = os.path.join(DIR, "secrets", "bits-store-token-key.enc.pem")
# ... and the build jobs' tokens' key, in the same proxy, on a route of its own.
BUILD_SLOT = "bits-store-build-token-key"
BUILD_KEY = os.path.join(DIR, "secrets", "bits-store-build-token-key.enc.pem")
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
    """A step failed; the message names it, never a value. detail: what docker said,
    shown at the terminal only (the host helper does not pass it on)."""

    def __init__(self, message, detail=""):
        super().__init__(message)
        self.detail = detail


class WrongPassphrase(UnlockError):
    """The passphrase did not decrypt (counted by the host helper's lockout)."""


def _compose(args, value=None, env=None):
    try:
        r = subprocess.run(["docker", "compose"] + args, cwd=DIR, capture_output=True, timeout=120,
                           input=value.encode() if value is not None else None, env=env)
    except FileNotFoundError:
        raise UnlockError("docker is not installed or not on PATH")
    except subprocess.TimeoutExpired:
        raise UnlockError("docker compose %s did not answer in 120 s" % args[0])
    return r.returncode, r.stdout.decode(), r.stderr.decode()


def decrypt_signing_seed(enc_path, passphrase):
    """The raw Ed25519 seed of the encrypted PEM, base64."""
    from cryptography.hazmat.primitives import serialization as s
    try:
        with open(enc_path, "rb") as f:
            pem = f.read()
    except OSError:
        raise UnlockError("no encrypted key at: %s (run encrypt-signing-key.sh first)" % enc_path)
    try:
        key = s.load_pem_private_key(pem, password=passphrase)
        raw = key.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
    except (ValueError, TypeError):
        raise WrongPassphrase("wrong passphrase, or not an encrypted Ed25519 key")
    return base64.b64encode(raw).decode()


def push(slot, value, service):
    """Pushes a value into a proxy's in-memory slot; returns what the proxy said."""
    code, out, err = _compose(["exec", "-T", service, "security-proxy", "push", slot,
                               "--socket", INGEST], value)
    if code:
        raise UnlockError("push %s into %s failed (exit %d)" % (slot, service, code), (err or out).strip()[:300])
    return out


def signing_key_id(service=SIGNER, route=SIGN_ROUTE):
    """The full key id the signer has loaded, read through its sign route."""
    code, keyid, err = _compose(["exec", "-T", service, "python3", "-", route, AGENT], PUBKEY)
    if code:
        raise UnlockError("the sign route did not answer (exit %d)" % code, err.strip()[-300:])
    return keyid.strip()


def unlock_signer(passphrase, enc_path=SIGN_KEY, store_path=STORE_KEY, build_path=BUILD_KEY):
    """Decrypts and pushes the signing key, and the store tokens' keys there are;
    returns (what the proxy said, key id)."""
    seeds = [(SIGN_SLOT, decrypt_signing_seed(enc_path, passphrase), SIGNER)]  # all, before pushing
    for slot, path in ((STORE_SLOT, store_path), (BUILD_SLOT, build_path)):
        if os.path.isfile(path):
            seeds.append((slot, decrypt_signing_seed(path, passphrase), STORE_SIGNER))
    said = ""
    for slot, seed, service in seeds:
        if service != STORE_SIGNER:
            said += push(slot, seed, service)
            continue
        try:                    # the manifest signer's key is in: this one only reports
            if not running(STORE_SIGNER):
                raise UnlockError("%s is not running" % STORE_SIGNER)
            said += push(slot, seed, service)
        except UnlockError as e:
            said += "%s not pushed: %s\n" % (slot, e)
    return said, signing_key_id()


def store_token_key(passphrase, path=STORE_KEY, sign_path=SIGN_KEY):
    """The store tokens' public key, base64url (bits-store's "x"), of the key at
    *path*: made first if missing, encrypted with the signing key's passphrase."""
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    decrypt_signing_seed(sign_path, passphrase)          # the signing key's passphrase
    if not os.path.isfile(path):          # written whole beside it, then linked in place
        pem = Ed25519PrivateKey.generate().private_bytes(
            s.Encoding.PEM, s.PrivateFormat.PKCS8, s.BestAvailableEncryption(passphrase))
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path))
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(pem)
            with contextlib.suppress(FileExistsError):          # made meanwhile: that one
                os.link(tmp, path)
        finally:
            os.unlink(tmp)
    seed = base64.b64decode(decrypt_signing_seed(path, passphrase))
    pub = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        s.Encoding.Raw, s.PublicFormat.Raw)
    return base64.urlsafe_b64encode(pub).rstrip(b"=").decode()


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
        raise WrongPassphrase("wrong passphrase, or %s is damaged" % path)
    return json.loads(plain)


def save_service_secrets(passphrase, secrets, path=SECRETS_FILE):
    """Encrypts *secrets* to *path* in one step, mode 600, its owner kept (a new file:
    its directory's), so `make secret` still reads what the host helper wrote."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_scrypt(passphrase, salt)).encrypt(
        nonce, json.dumps(secrets, sort_keys=True).encode(), b"service-secrets/1")
    box = {"v": 1, "kdf": "scrypt", "n": 2 ** 15, "r": 8, "p": 1,
           "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
           "ct": base64.b64encode(ct).decode()}
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        os.makedirs(directory, mode=0o700)
        parent = os.stat(os.path.dirname(directory))
        if os.getuid() == 0:  # the host helper: the checkout's owner, not root
            os.chown(directory, parent.st_uid, parent.st_gid)
    st = os.lstat(path) if os.path.lexists(path) else os.stat(directory)
    fd, tmp = tempfile.mkstemp(prefix=".service-secrets.", dir=directory)
    try:
        with os.fdopen(fd, "w") as f:
            os.fchmod(fd, 0o600)
            if (st.st_uid, st.st_gid) != (os.getuid(), os.getgid()):
                os.fchown(fd, st.st_uid, st.st_gid)
            json.dump(box, f)
            f.flush()
            os.fsync(fd)
        os.replace(tmp, path)
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)  # the rename lasts a crash
        finally:
            os.close(dfd)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextlib.contextmanager
def service_secrets_lock(path=SECRETS_FILE):
    """Held from load to save, by the host helper and service-secrets.py alike, so neither
    writes back an older copy over the other's change (a lock on the directory itself)."""
    import fcntl
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        yield
        return
    fd = os.open(directory, os.O_RDONLY)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX)
        yield
    finally:
        os.close(fd)


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


# Slots the proxy puts verbatim into a header that wants a scheme first: kept bare.
AS_HEADER = {"github-read": "Bearer "}


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
        value = secrets[slot]
        if slot in AS_HEADER and not value.startswith(AS_HEADER[slot]):
            value = AS_HEADER[slot] + value
        push(slot, value, service)
        where.setdefault(service, []).append(slot)
    return where


def main(argv):
    if argv[:1] in (["store-token-key"], ["store-build-token-key"]):
        build = argv[0] == "store-build-token-key"
        path = BUILD_KEY if build else STORE_KEY
        try:
            pub = store_token_key(getpass.getpass("Signing key passphrase: ").encode(), path)
        except UnlockError as e:
            sys.exit(str(e))
        kid = (_env_file().get("BITS_STORE_BUILD_TOKEN_KID") or "builds-1" if build else
               _env_file().get("BITS_STORE_TOKEN_KID") or "console-1")
        print("%s: in bits-store's config.json, under \"keys\":\n  \"%s\": "
              "{\"x\": \"%s\", \"signer\": \"%s\"}\nthen make unlock"
              % (path, kid, pub, "build" if build else "user"))
        return
    if not argv or argv[0] != "unlock-signer":
        sys.exit(__doc__.split("\n\n")[1])
    enc = argv[1] if len(argv) > 1 and argv[1] else "secrets/bits-sign-key.enc.pem"
    expect = argv[2] if len(argv) > 2 else ""
    if not os.path.isfile(enc):
        sys.exit("ERROR: no encrypted key at: %s (run encrypt-signing-key.sh first)" % enc)
    print(">> decrypting and pushing into slot '%s' (you will be prompted for the passphrase) ..."
          % SIGN_SLOT, flush=True)
    try:
        said, keyid = unlock_signer(getpass.getpass("Passphrase: ").encode(), enc)
    except UnlockError as e:
        sys.exit(str(e) + (": " + e.detail if e.detail else ""))
    sys.stdout.write(said)
    keyid16 = keyid[:16]
    print("   loaded key_id (16) = %s" % keyid16)
    if expect and keyid16 != expect:
        sys.exit("ERROR: loaded key_id %s != expected %s" % (keyid16, expect))
    print(">> OK: matches expected trust anchor %s" % expect if expect
          else ">> compare %s against the key_id bits ships (keys/*.pem)." % keyid16)


if __name__ == "__main__":
    main(sys.argv[1:])
