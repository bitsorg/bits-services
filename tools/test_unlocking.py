# SPDX-License-Identifier: Apache-2.0
"""Tests for unlocking.py and service-secrets.py's use of it (docker compose faked)."""

import importlib.util
import os
import sys
import tempfile
import unittest

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

    def tearDown(self):
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
        said, keyid = ul.unlock_signer(b"test-pass", path)
        self.assertEqual((said, keyid), ("pushed slot 'bits-sign-key'\n", "43fd71705f29a075ffff"))
        args, value = self.fake.calls[0]
        self.assertEqual(args, ["exec", "-T", "security-proxy", "security-proxy", "push", "bits-sign-key",
                                "--socket", ul.INGEST])
        import base64
        raw = key.private_bytes(s.Encoding.Raw, s.PrivateFormat.Raw, s.NoEncryption())
        self.assertEqual(value, base64.b64encode(raw).decode())

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
        with self.assertRaises(ul.UnlockError):
            ul.load_service_secrets(b"wrong-pass", ss.FILE)
        self.fake.running = ("credentials-proxy", "store-writer")
        where = ul.push_service_secrets(secrets)
        self.assertEqual(where, {"credentials-proxy": ["gitlab-read"],
                                 "store-writer": ["gitlab-mirror", "s3-access-b"]})
        pushes = [a[a.index("push") + 1] for a, _ in self.fake.calls if "push" in a]
        self.assertEqual(pushes[:2], [ul.CERT_SLOT, ul.CERT_SLOT])  # certificates first

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
