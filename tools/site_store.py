#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""The store's configuration for bits-admin (ADR bits-services 0004, K): bits-store's
config.json, the names of the keys in secrets/bits-store.env (never their values) and
the console's store-token key. A change is checked by bits-store itself (-check) before
it is written; the running store reloads config.json, new keys need make store-up.

    tools/site_store.py       # the JSON the host helper hands bits-admin
"""

import difflib
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_profile  # noqa: E402
import site_settings  # noqa: E402
import unlocking  # noqa: E402

DIR = site_profile.DIR
CREDENTIALS = os.path.join(DIR, "secrets", "bits-store.env")
# Key names: the store's own; never one root's docker compose reads (DOCKER_HOST, ...).
NAME = re.compile(r"BITS_STORE_[A-Z0-9_]{1,52}")
MAX_CONFIG, MAX_VALUE = 128 * 1024, 4096  # a request to the helper holds both
SIGNER, ROUTE, PREFIX = "store-token-signer", "bits-store-token-sign", "/sign/store"
# Run inside the signer's container: its gate token never leaves it.
PUBKEY = r"""
import base64, json, subprocess, sys, urllib.request
route, prefix, agent = sys.argv[1:4]
tok = subprocess.check_output(["security-proxy-token", route, "--socket", agent], text=True).strip()
addr = subprocess.check_output(["security-proxy-token", "--addr", "--socket", agent], text=True).strip()
req = urllib.request.Request(addr + prefix + "/pubkey", headers={"Authorization": "Bearer " + tok})
pub = base64.b64decode(json.load(urllib.request.urlopen(req))["publicKey"])
print(base64.urlsafe_b64encode(pub).rstrip(b"=").decode())
"""


class Refused(Exception):
    """A change that cannot be made: why, in names and rules, never a key's value."""


def config_path():
    """config.json in BITS_STORE_CONFIG_DIR, which must lie inside this checkout."""
    d = os.path.realpath(os.path.join(DIR, unlocking._env_file().get("BITS_STORE_CONFIG_DIR")
                                      or "./config/bits-store"))
    if not d.startswith(os.path.realpath(DIR) + os.sep):
        raise Refused("BITS_STORE_CONFIG_DIR: a directory inside %s" % DIR)
    return os.path.join(d, "config.json")


def _credentials():
    """{NAME: value} of secrets/bits-store.env: NAME='value' lines, as apply writes them."""
    text, _ = site_profile.read_regular(CREDENTIALS)
    out = {}
    for line in (text or "").splitlines():
        name, sep, value = line.partition("=")
        if sep and NAME.fullmatch(name.strip()):
            out[name.strip()] = value[1:-1] if len(value) > 1 and value[0] == value[-1] == "'" else value
    return out


def _current():
    text, _ = site_profile.read_regular(config_path(), MAX_CONFIG)
    creds, (_, st) = _credentials(), site_profile.read_regular(CREDENTIALS)
    base = hashlib.sha256(json.dumps([text, sorted(creds), st and st.st_mtime_ns]).encode()).hexdigest()
    return text or "", creds, base


def console_key():
    """The store-token signer's public key, base64url (bits-store's "x"); None if it
    does not answer (not running, no key pushed)."""
    code, out, _ = unlocking._compose(["exec", "-T", SIGNER, "python3", "-", ROUTE, PREFIX,
                                       unlocking.AGENT], PUBKEY)
    out = out.strip()
    return out if code == 0 and re.fullmatch(r"[A-Za-z0-9_-]{43}", out) else None


def collect():
    text, creds, base = _current()
    try:
        config = json.loads(text) if text else None
    except ValueError:
        config = None
    return {"config": config, "path": os.path.relpath(config_path(), DIR), "credentials": sorted(creds),
            "base": base, "console_key": console_key()}


def _named(config):
    """The key names the config's volumes name; each one of the store's own."""
    vols = config.get("volumes") if isinstance(config.get("volumes"), dict) else {}
    names = {v.get(k) for v in vols.values() if isinstance(v, dict)
             for k in ("access_key_env", "secret_key_env") if v.get(k)}
    compose = set(site_settings.compose_vars(open(os.path.join(DIR, "docker-compose.yml")).read()))
    for n in names:
        if not (isinstance(n, str) and NAME.fullmatch(n)) or n in compose:
            raise Refused("volumes: key name %r: BITS_STORE_<NAME>, not a setting of docker-compose.yml" % (n,))
    return names


def _proposed(config, credentials, current):
    """(config.json text, the keys after the change, what changes in them by name)."""
    if not isinstance(config, dict):
        raise Refused("config: a JSON object, as bits-store's config.json")
    named = _named(config)
    text = json.dumps(config, indent=1) + "\n"
    if len(text) > MAX_CONFIG:
        raise Refused("config: at most %d bytes" % MAX_CONFIG)
    if not isinstance(credentials or {}, dict):
        raise Refused("credentials: {NAME: value}, an empty value removes one")
    merged, changes = dict(current), {}
    for name, value in (credentials or {}).items():
        if not (isinstance(name, str) and name in named or value == "" and name in merged):
            raise Refused("credentials: %r is not a key name the volumes name" % (name,))
        if not (isinstance(value, str) and len(value) <= MAX_VALUE and "'" not in value
                and (value == "" or value.isprintable())):
            raise Refused("credentials: %s: one line of at most %d characters, no '" % (name, MAX_VALUE))
        if value == "" and name in merged:
            del merged[name]
            changes[name] = "will remove"
        elif value and merged.get(name) != value:
            merged[name] = value
            changes[name] = "will set"
    return text, merged, changes, named


def _check(text, creds, names):
    """bits-store -check on the proposed config.json with the proposed keys (passed in
    the environment, never in arguments; *names* no longer set are passed empty)."""
    # beside config.json: docker sees it (the helper's /tmp is private), the store ignores it
    tmp = tempfile.mkdtemp(prefix="check-", dir=os.path.dirname(config_path()))
    try:
        os.chmod(tmp, 0o755)
        fd = os.open(os.path.join(tmp, "config.json"), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(fd, "w") as f:
            os.fchmod(fd, 0o644)
            f.write(text)
        args = ["--profile", "bits-store", "run", "--rm", "--no-deps", "-T", "-v", tmp + ":/check:ro"]
        for name in sorted(names):
            args += ["-e", name if name in creds else name + "="]
        env = dict(os.environ, **{n: v for n, v in creds.items() if n in names})
        code, _, err = unlocking._compose(args + ["bits-store", "-check", "-config", "/check/config.json"],
                                          env=env)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if code:
        lines = [ln for ln in err.strip().splitlines() if ln.strip()]
        raise Refused("bits-store refuses it: %s" % (lines[-1][:300] if lines else "exit %d" % code))


def plan(config, credentials=None):
    """{base, diff, credentials: {NAME: will set|will remove}, restart}: what apply would do,
    once bits-store has taken the result."""
    if not os.path.isdir(os.path.dirname(config_path())):
        raise Refused("%s does not exist (DEPLOYMENT.md, \"The store service\")"
                      % os.path.relpath(os.path.dirname(config_path()), DIR))
    old, current, base = _current()
    text, merged, changes, named = _proposed(config, credentials, current)
    _check(text, merged, named)
    return {"base": base, "credentials": changes, "restart": bool(changes),
            "diff": list(difflib.unified_diff(old.splitlines(), text.splitlines(), "config.json", "config.json",
                                              lineterm=""))}


def apply(config, credentials, base):
    """Writes config.json (644; the old one kept as .bak-<time>) and the keys (600), if
    nothing changed since the plan and bits-store takes the result."""
    old, current, now = _current()
    if base != now:
        raise Refused("the store's configuration changed since the plan: plan again")
    text, merged, changes, named = _proposed(config, credentials, current)
    _check(text, merged, named)
    written, backup = site_profile.write_env(config_path(), text, mode=0o644)
    if changes:  # quoted: compose takes the value as written, $ and # included
        site_profile.write_env(CREDENTIALS, "".join("%s='%s'\n" % kv for kv in sorted(merged.items())))
    return {"written": written, "backup": os.path.basename(backup) if backup else None,
            "credentials": sorted(changes), "restart": bool(changes)}


if __name__ == "__main__":
    json.dump(collect(), sys.stdout, indent=1)
