#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""service-secrets.py — the services' secrets for the credentials proxy (M6).

The GitLab tokens and store keys the backend and the worker used to read from
.env live here instead: in one passphrase-encrypted file (secrets/
service-secrets.enc, scrypt + AES-256-GCM), pushed into the credentials proxy's
memory by `make unlock`. They never touch disk in the clear, and the services
never see them: the proxy adds them to requests on the way out.

    tools/service-secrets.py set <slot>     # prompts the value (or reads stdin)
    tools/service-secrets.py remove <slot>
    tools/service-secrets.py list           # slot names only
    tools/service-secrets.py import-env     # take the ones still in .env (once)
    tools/service-secrets.py push           # into the running proxy (make unlock)
    tools/service-secrets.py check          # through the proxy, from the services

Each prompts for the passphrase. Slots (see security-proxy/credentials.sample.json):

    gitlab-read    read_api token: pipelines, jobs, logs, bits-manifests
    gitlab-ops     the project token for pipeline actions and variables
    gitlab-groups  read_api token that can read the admin groups' members
    s3-access-<bucket>, s3-secret-<bucket>    the store's keypair

Rotating one: `set` it, then `push` (or `make unlock`): the proxy uses the new
value at once; the services do not restart.
"""

import argparse
import base64
import datetime
import getpass
import json
import os
import subprocess
import sys

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILE = os.environ.get("SERVICE_SECRETS", os.path.join(DIR, "secrets", "service-secrets.enc"))
SERVICE = os.environ.get("CREDENTIALS_PROXY_SERVICE", "credentials-proxy")
INGEST = "/run/security-proxy-ingest/ingest.sock"
CERT_SLOT = "client-cert"
# .env variables `import-env` takes, by slot.
# gitlab-read as the services read today: with the read token, else the ops token.
FROM_ENV = {"gitlab-read": ("BITS_FORGE_READ_TOKEN", "BITS_FORGE_OPS_TOKEN"),
            "gitlab-ops": ("BITS_FORGE_OPS_TOKEN",),
            "gitlab-groups": ("BITS_ADMIN_RESOLVE_TOKEN",)}


def _key(passphrase, salt, n=2 ** 15, r=8, p=1):
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase)


def load(passphrase):
    if not os.path.exists(FILE):
        return {}
    box = json.load(open(FILE))
    salt, nonce = base64.b64decode(box["salt"]), base64.b64decode(box["nonce"])
    try:
        plain = AESGCM(_key(passphrase, salt, box["n"], box["r"], box["p"])).decrypt(
            nonce, base64.b64decode(box["ct"]), b"service-secrets/1")
    except Exception:
        sys.exit("wrong passphrase, or %s is damaged" % FILE)
    return json.loads(plain)


def save(passphrase, secrets):
    salt, nonce = os.urandom(16), os.urandom(12)
    ct = AESGCM(_key(passphrase, salt)).encrypt(
        nonce, json.dumps(secrets, sort_keys=True).encode(), b"service-secrets/1")
    box = {"v": 1, "kdf": "scrypt", "n": 2 ** 15, "r": 8, "p": 1,
           "salt": base64.b64encode(salt).decode(), "nonce": base64.b64encode(nonce).decode(),
           "ct": base64.b64encode(ct).decode()}
    os.makedirs(os.path.dirname(FILE), exist_ok=True)
    tmp = FILE + ".tmp"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(box, fh)
    os.replace(tmp, FILE)


def passphrase(new=False):
    p = getpass.getpass("Service-secrets passphrase: ").encode()
    if new and not os.path.exists(FILE):
        if len(p) < 8:
            sys.exit("passphrase too short (use >= 8 characters)")
        if p != getpass.getpass("Confirm passphrase: ").encode():
            sys.exit("passphrases do not match")
    return p


def _value(slot):
    if sys.stdin.isatty():
        v = getpass.getpass("Value for %s: " % slot)
    else:
        v = sys.stdin.read()
    v = v.strip()
    if not v:
        sys.exit("empty value")
    return v


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


def _push(slot, value):
    r = subprocess.run(["docker", "compose", "exec", "-T", SERVICE, "security-proxy", "push",
                        slot, "--socket", INGEST], input=value.encode(), cwd=DIR,
                       capture_output=True)
    if r.returncode:
        sys.exit("push %s failed: %s" % (slot, (r.stderr or r.stdout).decode().strip()[:300]))
    return r.stdout.decode()


CHECK = r'''
import json, sys
from console_backend import config, credproxy, forge_ops
s = config.Settings()
out = {}
for kind in ("read", "ops", "groups"):
    if not credproxy.has(s, kind):
        out["gitlab-" + kind] = "no such route (not provided)"
        continue
    try:
        api, token = credproxy.gitlab(s, kind)
        import requests
        r = requests.get(api + "/user", headers={"PRIVATE-TOKEN": token}, timeout=20)
        out["gitlab-" + kind] = r.status_code if r.status_code != 200 else "ok as " + r.json().get("username", "?")
    except Exception as e:
        out["gitlab-" + kind] = "%s: %s" % (type(e).__name__, e)
bucket = (s.orch_store or "").split("::")[0][len("b3://"):].split("/")[0]
if bucket:
    try:
        credproxy.s3_client(s)[0].list_objects_v2(Bucket=bucket, Prefix="MANIFESTS/", MaxKeys=1)
        out["s3 " + bucket] = "ok"
    except Exception as e:
        out["s3 " + bucket] = "%s: %s" % (type(e).__name__, str(e)[:200])
print(json.dumps(out, indent=1))
'''


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("command", choices=["set", "remove", "list", "import-env", "push", "check"])
    ap.add_argument("slot", nargs="?")
    a = ap.parse_args()
    if a.command == "check":
        r = subprocess.run(["docker", "compose", "exec", "-T", "-e",
                            "BITS_CRED_PROXY_AGENT_SOCKET=/run/credentials-proxy/agent.sock",
                            "bits-orchestrator", "python3", "-c", CHECK], cwd=DIR)
        sys.exit(r.returncode)
    if a.command in ("set", "remove") and not a.slot:
        ap.error("%s needs a slot name" % a.command)
    p = passphrase(new=a.command in ("set", "import-env"))
    secrets = load(p)
    if a.command == "list":
        for k in sorted(secrets):
            print(k)
        return
    if a.command == "set":
        secrets[a.slot] = _value(a.slot)
        save(p, secrets)
        print("stored %s (%d slot(s)); push it with: make unlock" % (a.slot, len(secrets)))
    elif a.command == "remove":
        if secrets.pop(a.slot, None) is None:
            sys.exit("no slot %s" % a.slot)
        save(p, secrets)
        print("removed %s" % a.slot)
    elif a.command == "import-env":
        env = dict(_env_file(), **{k: v for k, v in os.environ.items() if k.startswith("BITS_")})
        took = []
        for slot, names in FROM_ENV.items():
            var = next((n for n in names if env.get(n)), None)
            if var:
                secrets[slot] = env[var]
                took.append("%s <- %s" % (slot, var))
            elif slot == "gitlab-groups":
                took.append("gitlab-groups: none in .env -- remove that route from the proxy's"
                            " config, so admins' groups are read with their own tokens as now")
        bucket = (env.get("BITS_ORCH_STORE", "").split("::")[0][len("b3://"):].split("/")[0])
        if bucket and env.get("BITS_ORCH_S3_ACCESS_KEY_ID") and env.get("BITS_ORCH_S3_SECRET_ACCESS_KEY"):
            secrets["s3-access-" + bucket] = env["BITS_ORCH_S3_ACCESS_KEY_ID"]
            secrets["s3-secret-" + bucket] = env["BITS_ORCH_S3_SECRET_ACCESS_KEY"]
            took.append("s3-access/secret-%s <- BITS_ORCH_S3_*" % bucket)
        save(p, secrets)
        print("\n".join(took) or "nothing found in .env")
        print("Next: make unlock; check; then set BITS_CRED_PROXY_AGENT_SOCKET in .env and"
              " remove those variables.")
    elif a.command == "push":
        if not secrets:
            sys.exit("no service secrets yet (tools/service-secrets.py set <slot>)")
        # (A new client certificate makes the proxy rebuild its HTTPS client:
        # requests in flight through it are cut, and retried by the services.)
        out = _push(CERT_SLOT, _throwaway_cert())
        if "tls: ready" not in out:
            sys.exit("the credentials proxy did not take the client certificate: %s" % out.strip())
        for slot in sorted(secrets):
            _push(slot, secrets[slot])
        print(">> pushed %d service secret(s) into %s: %s" % (len(secrets), SERVICE,
                                                             ", ".join(sorted(secrets))))


if __name__ == "__main__":
    main()
