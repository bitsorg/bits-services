# SPDX-License-Identifier: Apache-2.0
"""Tests for unlocking.py and service-secrets.py's use of it (docker compose faked)."""

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import unlocking as ul  # noqa: E402

from cryptography.hazmat.primitives import serialization as s  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey  # noqa: E402

spec = importlib.util.spec_from_file_location(
    "service_secrets", os.path.join(os.path.dirname(os.path.abspath(__file__)), "service-secrets.py"))
ss = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ss)


class FakeCompose:
    """Records docker compose calls; answers as a running proxy would."""

    def __init__(self, running=("credentials-proxy",)):
        self.calls, self.running = [], running

    def __call__(self, args, value=None):
        self.calls.append((args, value))
        if args[0] == "ps":
            return 0, "abc\n" if args[-1] in self.running else "", ""
        if "push" in args:
            return 0, ("tls: ready\n" if args[args.index("push") + 1] == ul.CERT_SLOT
                       else "pushed slot '%s'\n" % args[args.index("push") + 1]), ""
        if "python3" in args:
            assert "security-proxy-token" in value and "gate-token" not in " ".join(args)
            return 0, "43fd71705f29a075ffff\n", ""
        return 1, "", "unexpected"


class UnlockingTest(unittest.TestCase):
    def setUp(self):
        self.real, self.fake = ul._compose, FakeCompose()
        ul._compose = self.fake
        self.tmp = tempfile.TemporaryDirectory()
        self.admin = mock.patch.object(ul, "ADMIN_KEY", os.path.join(self.tmp.name, "no-admin-key"))
        self.admin.start()                  # never the checkout's own

    def tearDown(self):
        self.admin.stop()
        ul._compose = self.real
        self.tmp.cleanup()

    def key(self, passphrase=b"test-pass"):
        key = Ed25519PrivateKey.generate()
        path = os.path.join(self.tmp.name, "k.enc.pem")
        with open(path, "wb") as f:
            f.write(key.private_bytes(s.Encoding.PEM, s.PrivateFormat.PKCS8,
                                      s.BestAvailableEncryption(passphrase)))
        return path, key

    def test_unlock_signer(self):
        path, key = self.key()
        said, keyid = ul.unlock_signer(b"test-pass", path, os.path.join(self.tmp.name, "none"))
        self.assertEqual((said, keyid), ("pushed slot 'bits-sign-key'\n", "43fd71705f29a075ffff"))
        args, value = self.fake.calls[0]
        self.assertEqual(args, ["exec", "-T", "security-proxy", "security-proxy", "push", "bits-sign-key",
                                "--socket", ul.INGEST])
        import base64
        raw = key.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
        self.assertEqual(value, base64.b64encode(raw).decode())

    def test_the_store_tokens_key(self):
        import base64
        path, _ = self.key()
        store = os.path.join(self.tmp.name, "store.enc.pem")
        with self.assertRaises(ul.WrongPassphrase):                       # not the signing key's
            ul.store_token_key(b"other-pass", store, path)
        self.assertFalse(os.path.exists(store))
        pub = ul.store_token_key(b"test-pass", store, path)
        self.assertEqual(oct(os.stat(store).st_mode & 0o777), "0o600")
        self.assertEqual(ul.store_token_key(b"test-pass", store, path), pub)   # made once
        seed = base64.b64decode(ul.decrypt_signing_seed(store, b"test-pass"))
        raw = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
            s.Encoding.Raw, s.PublicFormat.Raw)
        self.assertEqual(base64.urlsafe_b64decode(pub + "="), raw)
        said, _ = ul.unlock_signer(b"test-pass", path, store)           # its proxy is not running
        self.assertIn("bits-store-token-key not pushed: store-token-signer is not running", said)
        self.assertEqual([a[a.index("push") + 1] for a, _ in self.fake.calls if "push" in a],
                         ["bits-sign-key"])
        real_push = ul.push

        def refusing(slot, value, service):                             # a failed push only reports
            if service == "store-token-signer":
                raise ul.UnlockError("refused")
            return real_push(slot, value, service)
        with mock.patch.object(ul, "push", refusing):
            self.fake.running = ("store-token-signer",)
            said, _ = ul.unlock_signer(b"test-pass", path, store)
        self.assertIn("bits-store-token-key not pushed: refused", said)
        self.fake.running, self.fake.calls[:] = ("store-token-signer",), []
        ul.unlock_signer(b"test-pass", path, store)                     # into its own proxy
        pushed = {a[a.index("push") + 1]: (a[2], v) for a, v in self.fake.calls if "push" in a}
        self.assertEqual(pushed, {"bits-sign-key": ("security-proxy", mock.ANY),
                                  "bits-store-token-key": ("store-token-signer",
                                                           base64.b64encode(seed).decode())})
        with open(store, "wb") as f:                                    # one it cannot decrypt
            f.write(b"damaged")
        self.fake.calls.clear()
        with self.assertRaises(ul.UnlockError):
            ul.unlock_signer(b"test-pass", path, store)
        self.assertEqual(self.fake.calls, [])                           # nothing pushed
        self.assertEqual([f for f in os.listdir(self.tmp.name) if f.startswith("tmp")], [])

    def test_the_build_tokens_key_goes_in_beside_it(self):
        path, _ = self.key()
        store, build = (os.path.join(self.tmp.name, n) for n in ("store.enc.pem", "build.enc.pem"))
        pubs = {ul.store_token_key(b"test-pass", store, path), ul.store_token_key(b"test-pass", build, path)}
        self.assertEqual(len(pubs), 2)                                  # two keys
        self.fake.running = ("store-token-signer",)
        ul.unlock_signer(b"test-pass", path, store, build)
        pushed = {a[a.index("push") + 1]: a[2] for a, _ in self.fake.calls if "push" in a}
        self.assertEqual(pushed, {"bits-sign-key": "security-proxy",
                                  "bits-store-token-key": "store-token-signer",
                                  "bits-store-build-token-key": "store-token-signer"})
        self.fake.calls.clear()
        ul.unlock_signer(b"test-pass", path, store, os.path.join(self.tmp.name, "none"))
        self.assertNotIn("bits-store-build-token-key",
                         [a[a.index("push") + 1] for a, _ in self.fake.calls if "push" in a])

    def test_the_admin_tokens_key(self):
        path, _ = self.key()
        admin = os.path.join(self.tmp.name, "admin.enc.pem")
        pub = ul.store_token_key(b"test-pass", admin, path)
        self.fake.running = ("store-token-signer",)
        none = os.path.join(self.tmp.name, "none")
        ul.unlock_signer(b"test-pass", path, none, none, none, admin)
        pushed = {a[a.index("push") + 1]: a[2] for a, _ in self.fake.calls if "push" in a}
        self.assertEqual(pushed, {"bits-sign-key": "security-proxy",
                                  "bits-store-admin-token-key": "store-token-signer"})
        out = io.StringIO()
        def made(_, p):
            self.assertEqual(p, ul.ADMIN_KEY)                           # its own key, no other
            return pub
        with mock.patch.object(ul, "store_token_key", made), \
             mock.patch.object(ul, "_env_file", lambda: {}), \
             mock.patch.object(ul.getpass, "getpass", lambda *a: "test-pass"), \
             contextlib.redirect_stdout(out):
            ul.main(["store-admin-token-key"])
        self.assertIn('"admin-1": {"x": "%s", "signer": "admin"}' % pub, out.getvalue())
        for cmd, env, want in (("store-token-key", {"BITS_STORE_TOKEN_KID": "console-2"}, '"console-2": {"x": "P", "signer": "user"}'),
                               ("store-build-token-key", {}, '"builds-1": {"x": "P", "signer": "build"}')):
            out = io.StringIO()
            with mock.patch.object(ul, "store_token_key", lambda *a: "P"), \
                 mock.patch.object(ul, "_env_file", lambda: env), \
                 mock.patch.object(ul.getpass, "getpass", lambda *a: "test-pass"), \
                 contextlib.redirect_stdout(out):
                ul.main([cmd])
            self.assertIn(want, out.getvalue())

    def test_the_restricted_builds_key(self):
        import base64
        import hashlib
        path, _ = self.key()
        restricted = os.path.join(self.tmp.name, "restricted.enc.pem")
        pub = ul.store_token_key(b"test-pass", restricted, path)
        self.fake.running = ("store-token-signer",)
        none = os.path.join(self.tmp.name, "none")
        ul.unlock_signer(b"test-pass", path, none, none, restricted)
        pushed = {a[a.index("push") + 1]: a[2] for a, _ in self.fake.calls if "push" in a}
        self.assertEqual(pushed, {"bits-sign-key": "security-proxy",
                                  "bits-restricted-sign-key": "store-token-signer"})
        pem, kid = ul.restricted_pem(pub)
        raw = s.load_pem_public_key(pem.encode()).public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)
        self.assertEqual(raw, base64.urlsafe_b64decode(pub + "="))
        self.assertEqual(kid, hashlib.sha256(raw).hexdigest()[:16])     # bits' key_id
        out = io.StringIO()
        def made(_, path):
            self.assertEqual(path, ul.RESTRICTED_KEY)                     # its own key, no other
            return pub
        with mock.patch.object(ul, "store_token_key", made), \
             mock.patch.object(ul.getpass, "getpass", lambda *a: "test-pass"), \
             contextlib.redirect_stdout(out):
            ul.main(["restricted-sign-key"])
        self.assertIn(pem, out.getvalue())
        self.assertIn("keys/restricted/", out.getvalue())
        self.assertIn("key id %s" % kid, out.getvalue())
        # bits' key_id of a fixed key (RFC 8032's test 1 public key)
        fixed = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        self.assertEqual(ul.restricted_pem(fixed)[1], "21fe31dfa154a261")

    def test_wrong_passphrase_pushes_nothing(self):
        path, _ = self.key()
        with self.assertRaises(ul.UnlockError) as e:
            ul.unlock_signer(b"wrong", path)
        self.assertEqual(str(e.exception), "wrong passphrase, or not an encrypted Ed25519 key")
        self.assertEqual(self.fake.calls, [])

    def test_service_secrets_round_trip_and_push(self):
        ss.FILE = os.path.join(self.tmp.name, "service-secrets.enc")
        ss.save(b"secret-pass", {"gitlab-read": "glpat-r", "s3-access-b": "AK", "gitlab-mirror": "glpat-m"})
        secrets = ul.load_service_secrets(b"secret-pass", ss.FILE)
        self.assertEqual(oct(os.stat(ss.FILE).st_mode & 0o777), "0o600")
        self.assertEqual([f for f in os.listdir(self.tmp.name) if f.startswith(".service-secrets.")], [])
        with self.assertRaises(ul.UnlockError):
            ul.load_service_secrets(b"wrong-pass", ss.FILE)
        self.fake.running = ("credentials-proxy", "store-writer")
        where = ul.push_service_secrets(secrets)
        self.assertEqual(where, {"credentials-proxy": ["gitlab-read"],
                                 "store-writer": ["gitlab-mirror", "s3-access-b"]})
        pushes = [a[a.index("push") + 1] for a, _ in self.fake.calls if "push" in a]
        self.assertEqual(pushes[:2], [ul.CERT_SLOT, ul.CERT_SLOT])  # certificates first

    def test_service_secrets_lock(self):
        import fcntl
        path = os.path.join(self.tmp.name, "service-secrets.enc")
        with ul.service_secrets_lock(path):
            fd = os.open(self.tmp.name, os.O_RDONLY)
            try:
                with self.assertRaises(BlockingIOError):
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)            # held
            finally:
                os.close(fd)
        fd = os.open(self.tmp.name, os.O_RDONLY)
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)                         # released
        os.close(fd)

    def test_github_read_is_pushed_as_a_header(self):
        self.fake.running = ("credentials-proxy",)
        ul.push_service_secrets({"github-read": "ghp_x", "gitlab-read": "glpat-r"})
        pushed = {a[a.index("push") + 1]: i for a, i in self.fake.calls if "push" in a}
        self.assertEqual(pushed["github-read"], "Bearer ghp_x")
        self.assertEqual(pushed["gitlab-read"], "glpat-r")
        ul.push_service_secrets({"github-read": "Bearer ghp_x"})               # stored with it: once
        pushed = [i for a, i in self.fake.calls if "push" in a and a[a.index("push") + 1] == "github-read"]
        self.assertEqual(pushed[-1], "Bearer ghp_x")

    def test_push_if_running_skips_a_stopped_proxy(self):
        self.fake.running = ()
        out = io.StringIO()
        with mock.patch.object(sys, "argv", ["service-secrets.py", "push", "--if-running"]), \
                mock.patch.object(ss, "passphrase", lambda new=False: self.fail("asked for the passphrase")), \
                contextlib.redirect_stdout(out):
            ss.main()
        self.assertIn("not pushed: credentials-proxy is not running", out.getvalue())
        self.assertFalse([a for a, _ in self.fake.calls if "push" in a])
        self.fake.running = ("credentials-proxy",)                             # running: it goes on
        with mock.patch.object(sys, "argv", ["service-secrets.py", "push", "--if-running"]), \
                mock.patch.object(ss, "passphrase", mock.Mock(side_effect=KeyboardInterrupt)) as asked:
            with self.assertRaises(KeyboardInterrupt):
                ss.main()
        asked.assert_called_once()

    def test_writer_configured_but_down(self):
        real = ul._writer_configured
        ul._writer_configured = lambda: True
        try:
            with self.assertRaises(ul.UnlockError) as e:
                ul.push_service_secrets({"s3-access-b": "AK"})
        finally:
            ul._writer_configured = real
        self.assertIn("store-writer is configured but not running", str(e.exception))
        self.assertFalse([a for a, _ in self.fake.calls if "push" in a])


if __name__ == "__main__":
    unittest.main()


class RealPassphraseTest(unittest.TestCase):
    """The helper's lockout counts WrongPassphrase: both real paths raise it."""

    def test_both_raise_wrong_passphrase(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "k.enc.pem")
            with open(path, "wb") as f:
                f.write(Ed25519PrivateKey.generate().private_bytes(
                    s.Encoding.PEM, s.PrivateFormat.PKCS8, s.BestAvailableEncryption(b"right")))
            with self.assertRaises(ul.WrongPassphrase):
                ul.decrypt_signing_seed(path, b"wrong")
            ss.FILE = os.path.join(d, "service-secrets.enc")
            ss.save(b"right-pass", {"a": "b"})
            with self.assertRaises(ul.WrongPassphrase):
                ul.load_service_secrets(b"wrong-pass", ss.FILE)
            with self.assertRaises(ul.UnlockError) as e:
                ul.decrypt_signing_seed(os.path.join(d, "missing.pem"), b"x")
            self.assertNotIsInstance(e.exception, ul.WrongPassphrase)

    def test_push_error_keeps_the_detail_apart(self):
        real = ul._compose
        ul._compose = lambda args, value=None: (1, "", "error: bad value " + (value or ""))
        try:
            with self.assertRaises(ul.UnlockError) as e:
                ul.push("slot", "s3cr3t-value", "credentials-proxy")
        finally:
            ul._compose = real
        self.assertEqual(str(e.exception), "push slot into credentials-proxy failed (exit 1)")
        self.assertNotIn("s3cr3t", str(e.exception))
