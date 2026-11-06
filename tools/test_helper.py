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
        self.state, self.calls = "no key", []

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
            return {"gitlab-read": "glpat-x"}
        def check(pw):
            self.calls.append(("check", pw))
            if pw != b"right-pass-9":
                raise helper.unlocking.WrongPassphrase("wrong passphrase, or not an encrypted Ed25519 key")
            return "c2VlZA=="
        return {"health": lambda: {"security-proxy": "healthy"}, "check": check,
                "signer": lambda: (self.state, "43fd71705f29a075ffff" if self.state == "loaded" else ""),
                "unlock": unlock, "load": load,
                "push": lambda secrets: {"credentials-proxy": sorted(secrets)}}


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
