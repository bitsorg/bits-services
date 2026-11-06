# SPDX-License-Identifier: Apache-2.0
"""Tests for bits-admin-helper.py (the unlocking functions faked)."""

import contextlib
import importlib.util
import io
import json
import os
import socket
import stat
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
spec = importlib.util.spec_from_file_location("helper", os.path.join(HERE, "bits-admin-helper.py"))
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
UnlockError = helper.unlocking.UnlockError


class Fakes:
    def __init__(self):
        self.state, self.calls, self.saved, self.exists, self.push_error = "no key", [], None, True, None

    def ops(self):
        def unlock(pw):
            self.calls.append(("unlock", pw))
            if pw != b"right-pass-9":
                raise helper.unlocking.WrongPassphrase("wrong passphrase, or not an encrypted Ed25519 key")
            self.state = "loaded"
            return "pushed\n", "43fd71705f29a075ffff"

        def load(pw):
            if pw != b"right-pass-9":
                raise helper.unlocking.WrongPassphrase("wrong passphrase, or secrets/service-secrets.enc is damaged")
            return dict(self.saved) if self.saved is not None else {"gitlab-read": "glpat-x"}

        def check(pw):
            self.calls.append(("check", pw))
            if pw != b"right-pass-9":
                raise helper.unlocking.WrongPassphrase("wrong passphrase, or not an encrypted Ed25519 key")
            return "c2VlZA=="
        def save(pw, secrets):
            self.calls.append(("save", pw, dict(secrets)))
            self.saved = dict(secrets)

        @contextlib.contextmanager
        def lock():
            self.calls.append(("lock",))
            yield
            self.calls.append(("unlock-file",))

        def push(secrets):
            if isinstance(self.push_error, Exception):
                raise self.push_error
            if self.push_error:
                raise helper.unlocking.UnlockError(self.push_error)
            return {"credentials-proxy": sorted(secrets)}
        return {"health": lambda: {"security-proxy": "healthy"}, "check": check,
                "signer": lambda: (self.state, "43fd71705f29a075ffff" if self.state == "loaded" else ""),
                "unlock": unlock, "load": load,
                "save": save, "exists": lambda: self.exists, "push": push, "lock": lock}


class HelperTest(unittest.TestCase):
    def setUp(self):
        self.fakes, self.t = Fakes(), [0.0]
        self.h = helper.Helper(self.fakes.ops(), now=lambda: self.t[0])

    def test_status_and_unlock(self):
        self.assertEqual(self.h.handle({"op": "status"})["signer"], "no key")
        self.assertEqual(self.h.handle({"op": "unlock-signer", "passphrase": "right-pass-9"}),
                         {"ok": True, "key_id16": "43fd71705f29a075"})
        self.assertEqual(self.h.handle({"op": "unlock-signer", "passphrase": "right-pass-9"}),
                         {"ok": False, "error": "the signer already holds a key"})
        self.assertEqual(self.h.handle({"op": "push-secrets", "passphrase": "right-pass-9"}),
                         {"ok": True, "pushed": {"credentials-proxy": ["gitlab-read"]}})

    def test_service_secrets(self):
        ask = lambda **r: self.h.handle(dict(r, passphrase=r.get("passphrase", "right-pass-9")))
        self.assertEqual(ask(op="secrets-list"), {"ok": True, "slots": ["gitlab-read"]})  # names only
        self.assertEqual(ask(op="secret-set", slot="gitlab-ops", value=" glpat-o \n"),
                         {"ok": True, "slots": ["gitlab-ops", "gitlab-read"],
                          "pushed": {"credentials-proxy": ["gitlab-ops", "gitlab-read"]}})
        self.assertEqual(self.fakes.saved["gitlab-ops"], "glpat-o")
        self.fakes.push_error = "credentials-proxy is not running"
        answer = ask(op="secret-remove", slot="gitlab-read")
        self.assertEqual((answer["ok"], answer["slots"], answer["push_error"]),
                         (True, ["gitlab-ops"], "credentials-proxy is not running"))  # saved all the same
        steps = [c[0] for c in self.fakes.calls if c[0] in ("lock", "save", "unlock-file")]
        self.assertEqual(steps[2:5], ["lock", "save", "unlock-file"])          # saved under the lock
        self.fakes.push_error = OSError("socket")
        answer = ask(op="secret-set", slot="gitlab-read", value="glpat-r")
        self.assertEqual((answer["ok"], answer["push_error"]), (True, "not pushed (OSError); make unlock pushes it"))
        self.fakes.push_error = None
        for request, said in ((dict(op="secret-remove", slot="gitlab-x"), "no slot gitlab-x"),
                              (dict(op="secret-set", slot="gitlab-read\n", value="x"), "a slot is a name"),
                              (dict(op="secret-set", slot="Bad Slot", value="x"), "a slot is a name"),
                              (dict(op="secret-set", slot="gitlab-ops", value="a\nb"), "one line"),
                              (dict(op="secret-set", slot="gitlab-ops", value=" "), "one line")):
            answer = ask(**request)
            self.assertFalse(answer["ok"], request)
            self.assertIn(said, answer["error"])
        saves = len([c for c in self.fakes.calls if c[0] == "save"])
        self.assertIn("wrong passphrase", ask(op="secret-set", slot="gitlab-ops", value="x", passphrase="wrong")["error"])
        self.assertEqual(len(self.h.failures), 1)
        self.assertEqual(len([c for c in self.fakes.calls if c[0] == "save"]), saves)  # nothing saved

    def test_a_first_secret_takes_the_signers_passphrase(self):
        self.fakes.exists = False
        self.assertTrue(self.h.handle({"op": "secret-set", "passphrase": "right-pass-9", "slot": "gitlab-ops",
                                       "value": "x"})["ok"])
        self.assertEqual([c[0] for c in self.fakes.calls if c[0] in ("check", "save")], ["check", "save"])
        self.fakes.calls, self.fakes.saved = [], None
        answer = self.h.handle({"op": "secret-set", "passphrase": "not-the-signers", "slot": "gitlab-ops", "value": "x"})
        self.assertFalse(answer["ok"])
        self.assertIn("wrong passphrase", answer["error"])
        self.assertEqual(len(self.h.failures), 1)                       # counts towards the lockout
        self.assertFalse([c for c in self.fakes.calls if c[0] == "save"])

    def test_hosts(self):
        calls = []
        h = helper.Helper(dict(self.fakes.ops(), hosts=lambda: calls.append(1) or {"host": "bits"}),
                          now=lambda: self.t[0])
        self.assertEqual(h.handle({"op": "hosts"}), {"host": "bits", "ok": True})
        h.handle({"op": "hosts"})
        self.t[0] += helper.HOSTS_TTL + 1
        h.handle({"op": "hosts"})
        self.assertEqual(len(calls), 2)  # the second answer came from the cache
        leak = ValueError("'s3cr3t' does not appear to be an IPv4 or IPv6 address")
        h = helper.Helper(dict(self.fakes.ops(), hosts=lambda: (_ for _ in ()).throw(leak)))
        with contextlib.redirect_stderr(io.StringIO()):
            answer = h.handle({"op": "hosts"})
        self.assertEqual(answer["ok"], False)
        self.assertNotIn("s3cr3t", json.dumps(answer))

    def test_settings(self):
        h = helper.Helper(dict(self.fakes.ops(), settings=lambda: {"settings": []}))
        self.assertEqual(h.handle({"op": "settings"}), {"settings": [], "ok": True})
        for e in (ValueError("KEY: 'hunter2'"), AttributeError("hunter2")):
            bad = helper.Helper(dict(self.fakes.ops(), settings=lambda e=e: (_ for _ in ()).throw(e)))
            with contextlib.redirect_stderr(io.StringIO()) as err:
                answer = bad.handle({"op": "settings"})
            self.assertEqual(answer["ok"], False)
            self.assertNotIn("hunter2", json.dumps(answer) + err.getvalue())

    def test_settings_plan_and_apply(self):
        seen = []
        ops = dict(self.fakes.ops(), **{"settings-plan": lambda c: seen.append(("plan", c)) or {"base": "h", "diff": []},
                                        "settings-apply": lambda c, b: seen.append(("apply", c, b)) or
                                        {"written": True, "backup": ".env.bak-1", "keys": ["VM_RETENTION"]}})
        h = helper.Helper(ops)
        self.assertEqual(h.handle({"op": "settings-plan", "changes": {"set": {}}}), {"base": "h", "diff": [], "ok": True})
        with contextlib.redirect_stderr(io.StringIO()) as err:
            self.assertTrue(h.handle({"op": "settings-apply", "changes": {}, "base": "h"})["ok"])
        self.assertIn("settings-apply: VM_RETENTION", err.getvalue())
        self.assertEqual(seen[1], ("apply", {}, "h"))
        refusing = helper.Helper(dict(ops, **{"settings-plan": lambda c: (_ for _ in ()).throw(
            helper.site_settings.Refused("not here, they are secrets: X"))}))
        self.assertEqual(refusing.handle({"op": "settings-plan"}), {"ok": False, "error": "not here, they are secrets: X"})
        quoting = helper.Helper(dict(ops, **{"settings-plan": lambda c: (_ for _ in ()).throw(
            ValueError("invalid literal for int(): 'hunter2'"))}))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertNotIn("hunter2", json.dumps(quoting.handle({"op": "settings-plan"})))

    def test_check_runs_at_most_once_a_while(self):
        runs = []
        h = helper.Helper(dict(self.fakes.ops(), hosts=lambda: {"host": "bits"},
                               probe=lambda hosts: runs.append(hosts["host"]) or [{"target": "a:1", "ok": True}]),
                          now=lambda: self.t[0])
        answer = h.handle({"op": "check"})
        self.assertEqual(answer["results"], [{"target": "a:1", "ok": True}])
        self.assertIn("at", answer)
        h.handle({"op": "check"})
        self.assertEqual(runs, ["bits"])
        self.t[0] += helper.HOSTS_TTL + 1
        h.handle({"op": "check"})
        self.assertEqual(runs, ["bits", "bits"])
        real = helper.Helper().ops  # its probe is not the passphrase check
        self.assertIs(real["probe"], helper.site_hosts.check)
        self.assertIsNot(real["check"], real["probe"])
        failing = helper.Helper(dict(self.fakes.ops(), hosts=lambda: (_ for _ in ()).throw(ValueError("x"))))
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(failing.handle({"op": "check"})["ok"], False)

    def test_check_the_passphrase(self):
        check = lambda pw: self.h.handle({"op": "check-signer-passphrase", "passphrase": pw})
        self.assertEqual(check("right-pass-9"), {"ok": True})
        self.assertEqual(check("wrong-pass-7")["ok"], False)
        self.fakes.state = "loaded"  # allowed while loaded: the proxy is not touched
        self.assertEqual(check("right-pass-9"), {"ok": True})
        self.assertEqual([c[0] for c in self.fakes.calls], ["check"] * 3)
        for _ in range(helper.FAILURES - 1):  # wrong ones count towards the lockout
            check("wrong-pass-7")
        tried = len(self.fakes.calls)
        self.assertIn("too many wrong passphrases", check("right-pass-9")["error"])
        self.assertEqual(len(self.fakes.calls), tried)  # refused before decrypting

    def test_check_decrypts_the_real_key_file(self):
        from cryptography.hazmat.primitives import serialization as s
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        pem = Ed25519PrivateKey.generate().private_bytes(
            s.Encoding.PEM, s.PrivateFormat.PKCS8, s.BestAvailableEncryption(b"right-pass-9"))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "bits-sign-key.enc.pem")
            with open(path, "wb") as f:
                f.write(pem)
            old, helper.unlocking.SIGN_KEY = helper.unlocking.SIGN_KEY, path
            try:
                real = helper.Helper()
                check = lambda pw: real.handle({"op": "check-signer-passphrase", "passphrase": pw})
                self.assertEqual(check("right-pass-9"), {"ok": True})
                self.assertIn("wrong passphrase", check("wrong-pass-7")["error"])
            finally:
                helper.unlocking.SIGN_KEY = old

    def test_wrong_passphrases_lock_out(self):
        for _ in range(helper.FAILURES):
            self.assertFalse(self.h.handle({"op": "unlock-signer", "passphrase": "wrong-pass-7"})["ok"])
        answer = self.h.handle({"op": "unlock-signer", "passphrase": "right-pass-9"})
        self.assertIn("too many wrong passphrases", answer["error"])
        self.assertEqual(len(self.fakes.calls), helper.FAILURES)  # the right one was not tried
        self.t[0] += helper.WINDOW + 1
        self.assertTrue(self.h.handle({"op": "unlock-signer", "passphrase": "right-pass-9"})["ok"])

    def test_bad_requests(self):
        for request in ({}, [], {"op": "rm -rf"}, {"op": "unlock-signer"},
                        {"op": "push-secrets", "passphrase": 1}):
            self.assertFalse(self.h.handle(request)["ok"], request)
        self.assertEqual(self.fakes.calls, [])

    def test_socket(self):
        with tempfile.TemporaryDirectory() as d:
            path, logged = os.path.join(d, "h.sock"), io.StringIO()
            ready = threading.Event()
            real_log = helper.log
            helper.log = lambda text: logged.write(text + "\n")
            threading.Thread(target=helper.serve, daemon=True,
                             kwargs={"path": path, "gid": os.getgid(), "helper": self.h,
                                     "ready": ready.set}).start()
            try:
                self.assertTrue(ready.wait(5))
                self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o660)
                ask = lambda raw: self._ask(path, raw)
                self.assertTrue(ask(json.dumps({"op": "unlock-signer", "passphrase": "right-pass-9"}) + "\n")["ok"])
                self.assertEqual(ask("not json\n"), {"ok": False, "error": "bad request"})
                self.assertEqual(ask("x" * (helper.MAX_REQUEST + 10)), {"ok": False, "error": "bad request"})
                self.assertFalse(ask(json.dumps({"op": "unlock-signer", "passphrase": "wrong-pass-7"}) + "\n")["ok"])
                self.assertFalse(ask(json.dumps({"op": "x\nforged line", "passphrase": "p"}) + "\n")["ok"])
            finally:
                helper.log = real_log
            text = logged.getvalue()
            self.assertIn("op=unlock-signer ok=True", text)
            self.assertNotIn("right-pass-9", text)
            self.assertNotIn("wrong-pass-7", text)
            self.assertNotIn("forged line", text)

    def test_the_group_must_match(self):
        real = helper.GROUP, helper.GID
        try:
            helper.GROUP = "no-such-group-here"
            with self.assertRaises(SystemExit):
                helper.socket_gid()
            import grp as g
            helper.GROUP, helper.GID = g.getgrgid(os.getgid()).gr_name, os.getgid() + 1
            with self.assertRaises(SystemExit):
                helper.socket_gid()
            helper.GID = os.getgid()
            self.assertEqual(helper.socket_gid(), os.getgid())
        finally:
            helper.GROUP, helper.GID = real

    def _ask(self, path, raw):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as c:
            c.settimeout(5)
            c.connect(path)
            try:
                c.sendall(raw.encode())
            except OSError:
                pass
            return json.loads(c.makefile().readline())


if __name__ == "__main__":
    unittest.main()
