#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""bits-admin-helper — the host side of bits-admin's unlock (ADR bits-services 0001, J).

A systemd service on the bits-services host, run as root since it uses docker
compose, which bits-admin may not. It listens on a unix socket that only the
bits-admin container's group can open; one JSON request per connection:

    {"op": "status"}
    {"op": "hosts"}       (tools/site_hosts.py: services, ports, networks, where they point)
    {"op": "check"}       (probes each connection of hosts once: health URLs, TCP connects)
    {"op": "settings"}    (tools/site_settings.py: every setting, secrets only as set or not)
    {"op": "settings-plan", "changes": {...}}           (what .env would become)
    {"op": "settings-apply", "changes": {...}, "base": "<hash>"}   (writes .env, a backup kept)
        changes: the Settings form's, or {"profile": "<site-profile.yaml>"} (also saved)
    {"op": "check-signer-passphrase", "passphrase": "..."}
    {"op": "unlock-signer", "passphrase": "..."}
    {"op": "push-secrets", "passphrase": "..."}
    {"op": "secrets-list", "passphrase": "..."}                    (slot names only)
    {"op": "secret-set", "passphrase": "...", "slot": "gitlab-read", "value": "..."}
    {"op": "secret-remove", "passphrase": "...", "slot": "gitlab-read"}

check-signer-passphrase decrypts the signing key and forgets it, so bits-admin can
check a passphrase before storing it (also while a key is loaded; the lockout below
applies). The others do what `make unlock` does (tools/unlocking.py). The helper
refuses an unlock while the
signer holds a key, stops after repeated wrong passphrases, and logs who asked
and the outcome, never a passphrase. By hand, as root:

    tools/bits-admin-helper.py serve
    tools/bits-admin-helper.py ask status|check-signer-passphrase|unlock-signer|push-secrets
"""

import collections
import getpass
import grp
import json
import os
import re
import socket
import struct
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_hosts  # noqa: E402
import site_settings  # noqa: E402
import unlocking  # noqa: E402

SOCKET = os.environ.get("BITS_ADMIN_HELPER_SOCKET", "/run/bits-admin-helper/helper.sock")
GROUP = os.environ.get("BITS_ADMIN_HELPER_GROUP", "bits-admin-helper")
GID = int(os.environ.get("BITS_ADMIN_HELPER_GID", "10004"))  # the one bits-admin's container joins
MAX_REQUEST = 262144  # a settings plan carries the changed values, or a site-profile.yaml
TIMEOUT = 15
FAILURES, WINDOW = 5, 600  # wrong passphrases allowed per window (seconds)
HOSTS_TTL = 30  # seconds a hosts answer is reused
OPS = ("status", "hosts", "check", "settings", "settings-plan", "settings-apply", "check-signer-passphrase",
       "unlock-signer", "push-secrets", "secrets-list", "secret-set", "secret-remove")
SECRET_OPS = ("secrets-list", "secret-set", "secret-remove")
SLOT = re.compile(r"[a-z0-9][a-z0-9.-]{0,62}")  # gitlab-read, s3-access-<bucket>; fullmatch
VALUE_MAX = 8192


def log(text):
    print(text, file=sys.stderr, flush=True)


def compose_health():
    """{service: state or health} of this checkout's containers."""
    code, out, _ = unlocking._compose(["ps", "--format", "json"])
    if code:
        return {}
    health = {}
    for line in out.splitlines():
        try:
            c = json.loads(line)
        except ValueError:
            continue
        health[c.get("Service", "?")] = c.get("Health") or c.get("State", "?")
    return health


def signer_state():
    """('down' | 'no key' | 'loaded', key id or '')."""
    if not unlocking.running(unlocking.SIGNER):
        return "down", ""
    try:
        return "loaded", unlocking.signing_key_id()
    except unlocking.UnlockError:
        return "no key", ""


class Helper:
    """The requests; the unlocking functions are passed in so tests can fake them."""

    def __init__(self, ops=None, now=time.monotonic):
        self.ops = ops or {"health": compose_health, "signer": signer_state,
                           "hosts": lambda: dict(site_hosts.collect(unlocking._compose, compose_health()),
                                                 up=site_hosts.scrape_up()),
                           "probe": site_hosts.check,
                           "settings": site_settings.collect,
                           "settings-plan": site_settings.plan, "settings-apply": site_settings.apply,
                           "check": lambda pw: unlocking.decrypt_signing_seed(unlocking.SIGN_KEY, pw),
                           "unlock": unlocking.unlock_signer,
                           "load": unlocking.load_service_secrets,
                           "save": unlocking.save_service_secrets,
                           "exists": lambda: os.path.exists(unlocking.SECRETS_FILE),
                           "lock": unlocking.service_secrets_lock,
                           "push": unlocking.push_service_secrets}
        self.now, self.failures, self.hosts, self.checked = now, collections.deque(), None, None

    def _locked_out(self):
        while self.failures and self.now() - self.failures[0] > WINDOW:
            self.failures.popleft()
        return len(self.failures) >= FAILURES

    def handle(self, request):
        op = request.get("op") if isinstance(request, dict) else None
        if op == "status":
            state, keyid = self.ops["signer"]()
            return {"ok": True, "signer": state, "key_id16": keyid[:16], "services": self.ops["health"]()}
        if op == "hosts":  # three compose runs: kept HOSTS_TTL, anyone in the group may ask
            if self.hosts and self.now() - self.hosts[0] < HOSTS_TTL:
                return self.hosts[1]
            try:
                answer = dict(self.ops["hosts"](), ok=True)
            except (unlocking.UnlockError, ValueError, OSError) as e:
                log("hosts failed: %s" % type(e).__name__)
                return {"ok": False, "error": "docker compose config failed; see the helper's journal"}
            self.hosts = (self.now(), answer)
            return answer
        if op == "settings":  # read-only: files on this host
            try:
                return dict(self.ops["settings"](), ok=True)
            except site_settings.Refused as e:  # a linked or odd .env: its name and the rule
                return {"ok": False, "error": str(e)}
            except Exception as e:  # never its text: it could quote a value
                log("settings failed: %s" % type(e).__name__)
                return {"ok": False, "error": "the settings could not be read; see the helper's journal"}
        if op in ("settings-plan", "settings-apply"):
            try:
                if op == "settings-plan":
                    return dict(self.ops[op](request.get("changes")), ok=True)
                done = self.ops[op](request.get("changes"), str(request.get("base", "")))
                log("settings-apply: %s%s" % (", ".join(done["keys"]) or "nothing changed",
                                              " and site-profile.yaml" if done.get("profile") else
                                              "; " + done["profile_error"] if done.get("profile_error") else ""))
                return dict(done, ok=True)
            except site_settings.Refused as e:  # its own words: names and rules, never a kept value
                return {"ok": False, "error": str(e)}
            except Exception as e:
                log("%s failed: %s" % (op, type(e).__name__))
                return {"ok": False, "error": "it failed; see the helper's journal"}
        if op == "check":  # probes other hosts: at most one run per HOSTS_TTL
            if self.checked and self.now() - self.checked[0] < HOSTS_TTL:
                return self.checked[1]
            hosts = self.handle({"op": "hosts"})
            if not hosts.get("ok"):
                return hosts
            answer = {"ok": True, "at": time.time(), "results": self.ops["probe"](hosts)}
            self.checked = (self.now(), answer)
            return answer
        if op not in OPS:
            return {"ok": False, "error": "unknown request"}
        passphrase = request.get("passphrase")
        if not isinstance(passphrase, str) or not passphrase:
            return {"ok": False, "error": "no passphrase"}
        if self._locked_out():
            return {"ok": False, "error": "too many wrong passphrases; try again in %d minutes" % (WINDOW // 60)}
        if op == "unlock-signer" and self.ops["signer"]()[0] == "loaded":
            return {"ok": False, "error": "the signer already holds a key"}
        try:
            if op == "check-signer-passphrase":
                self.ops["check"](passphrase.encode())  # the decrypted seed is dropped
                return {"ok": True}
            if op == "unlock-signer":
                _, keyid = self.ops["unlock"](passphrase.encode())
                return {"ok": True, "key_id16": keyid[:16]}
            if op in SECRET_OPS:
                return self._secrets(op, request, passphrase.encode())
            pushed = self.ops["push"](self.ops["load"](passphrase.encode()))
            return {"ok": True, "pushed": pushed}
        except unlocking.UnlockError as e:  # its message names a step, never a value
            if isinstance(e, unlocking.WrongPassphrase):
                self.failures.append(self.now())
            return {"ok": False, "error": str(e)}


    def _secrets(self, op, request, passphrase):
        """The service secrets by name; set or remove one, then push them all. Raises
        UnlockError (WrongPassphrase counts towards the lockout)."""
        slot, value = request.get("slot"), request.get("value")
        if op != "secrets-list" and not (isinstance(slot, str) and SLOT.fullmatch(slot)):
            return {"ok": False, "error": "a slot is a name like gitlab-read or s3-access-<bucket>"}
        if op == "secret-set" and not (isinstance(value, str) and value.strip() and len(value) <= VALUE_MAX
                                       and value.strip().isprintable()):
            return {"ok": False, "error": "a value is one line of at most %d characters" % VALUE_MAX}
        with self.ops["lock"]():
            if not self.ops["exists"]():
                self.ops["check"](passphrase)  # a first one takes the signer's passphrase
            secrets = self.ops["load"](passphrase)
            if op == "secrets-list":
                return {"ok": True, "slots": sorted(secrets)}
            if op == "secret-set":
                secrets[slot] = value.strip()
            elif secrets.pop(slot, None) is None:
                return {"ok": False, "error": "no slot %s" % slot}
            try:
                self.ops["save"](passphrase, secrets)
            except OSError as e:
                log("%s %s: not saved (%s)" % (op, slot, type(e).__name__))
                return {"ok": False, "error": "secrets/service-secrets.enc could not be written; see the helper's journal"}
        log("%s: %s" % (op, slot))
        answer = {"ok": True, "slots": sorted(secrets), "pushed": {}}
        try:
            if secrets:
                answer["pushed"] = self.ops["push"](secrets)
        except unlocking.UnlockError as e:  # saved; the next unlock pushes it
            answer["push_error"] = str(e)
        except Exception as e:  # saved all the same: say so, never its text
            log("%s %s: saved, not pushed (%s)" % (op, slot, type(e).__name__))
            answer["push_error"] = "not pushed (%s); make unlock pushes it" % type(e).__name__
        return answer


def _peer(conn):
    try:
        pid, uid, gid = struct.unpack("3i", conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED,
                                                            struct.calcsize("3i")))
        return "pid=%d uid=%d gid=%d" % (pid, uid, gid)
    except (OSError, AttributeError):
        return "peer unknown"


def _read(conn):
    data, deadline = b"", time.monotonic() + TIMEOUT
    while not data.endswith(b"\n"):
        if time.monotonic() > deadline:
            raise ValueError("request too slow")
        chunk = conn.recv(MAX_REQUEST + 1 - len(data))
        if not chunk:
            break
        data += chunk
        if len(data) > MAX_REQUEST:
            raise ValueError("request too long")
    return json.loads(data.decode())


def socket_gid():
    """The helper group's gid, which must be the one the bits-admin container joins."""
    try:
        gid = grp.getgrnam(GROUP).gr_gid
    except KeyError:
        sys.exit("no group %s: sudo groupadd --system --gid %d %s" % (GROUP, GID, GROUP))
    if gid != GID:
        sys.exit("group %s has gid %d, not %d, the one the bits-admin container joins" % (GROUP, gid, GID))
    return gid


def serve(path=SOCKET, gid=GID, helper=None, ready=None):
    helper = helper or Helper()
    if os.path.lexists(path):
        os.unlink(path)  # left by a previous run
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    old = os.umask(0o177)
    try:
        server.bind(path)
    finally:
        os.umask(old)
    os.chown(path, -1, gid)
    os.chmod(path, 0o660)
    server.listen(4)
    log("listening on %s (group %d)" % (path, gid))
    if ready:
        ready()
    while True:
        conn, _ = server.accept()
        with conn:
            try:
                _answer(conn, helper)
            except Exception as e:  # one caller never stops the helper
                log("connection failed: %s" % type(e).__name__)


def _answer(conn, helper):
    conn.settimeout(TIMEOUT)
    who, op = _peer(conn), "?"
    try:
        request = _read(conn)
    except (ValueError, OSError):
        request = None
    if request is None:
        answer = {"ok": False, "error": "bad request"}
    else:
        op = request.get("op") if isinstance(request, dict) else None
        op = op if op in OPS else "?"  # logged: only a known name
        try:
            answer = helper.handle(request)
        except Exception as e:  # never str(e): it could hold what was asked
            answer = {"ok": False, "error": "internal error: %s" % type(e).__name__}
    log("%s op=%s ok=%s %s" % (who, op, answer.get("ok"), answer.get("error", "")))
    conn.sendall((json.dumps(answer) + "\n").encode())


def ask(op, path=SOCKET):
    request = {"op": op}
    if op not in ("status", "hosts", "check", "settings"):
        request["passphrase"] = getpass.getpass("Passphrase: ")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
        c.settimeout(120)
        try:
            c.connect(path)
        except PermissionError:
            sys.exit("%s: permission denied (only root and group %d may ask)" % (path, GID))
        except (FileNotFoundError, ConnectionRefusedError):
            sys.exit("%s: the helper is not running (systemctl start bits-admin-helper)" % path)
        c.sendall((json.dumps(request) + "\n").encode())
        answer = json.loads(c.makefile().readline())
    print(json.dumps(answer, indent=1))
    return 0 if answer.get("ok") else 1


def main(argv):
    if argv[:1] == ["serve"]:
        serve(gid=socket_gid())
    elif len(argv) == 2 and argv[0] == "ask" and argv[1] in OPS:
        return ask(argv[1])
    else:
        sys.exit(__doc__.split("\n\n")[-1])


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
