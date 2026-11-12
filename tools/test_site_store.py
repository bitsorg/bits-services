# SPDX-License-Identifier: Apache-2.0
"""Tests for site_store.py: bits-store's configuration through the host helper (docker faked)."""

import json
import os
import stat
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_store as ss  # noqa: E402

REAL_CONFIG_PATH = ss.config_path

CONFIG = {"issuer": "https://bits-store.testbed", "audience": "testbed/store",
          "keys": {"console-1": {"x": "A" * 43, "signer": "user"}},
          "volumes": {"v": {"endpoint": "http://minio:9000", "bucket": "b", "region": "us-east-1",
                            "access_key_env": "BITS_STORE_V_AK", "secret_key_env": "BITS_STORE_V_SK", "allow_http": True}},
          "bindings": [{"prefix": "/store", "volume": "v", "key_prefix": "TARS"}]}


class Docker:
    """docker compose: run -check answers *check*; exec answers *pubkey*."""

    def __init__(self, check=(0, "ok\n", ""), pubkey=(0, "B" * 43 + "\n", "")):
        self.calls, self.check, self.pubkey = [], check, pubkey

    def __call__(self, args, value=None, env=None):
        self.calls.append((args, value, env))
        if args[:1] == ["exec"]:
            return self.pubkey
        if "-check" in args:
            src = next(a for a in args if a.endswith(":/check:ro")).split(":")[0]
            self.seen = json.load(open(os.path.join(src, "config.json")))
            return self.check
        return 1, "", "unexpected"


class SiteStoreTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.tmp.name
        os.makedirs(os.path.join(d, "config", "bits-store"))
        os.makedirs(os.path.join(d, "secrets"))
        with open(os.path.join(d, "docker-compose.yml"), "w") as f:
            f.write("services:\n  bits-store:\n    ports: ['${BITS_STORE_PORT:-8098}:8098']\n")
        self.cfg = os.path.join(d, "config", "bits-store", "config.json")
        with open(self.cfg, "w") as f:
            json.dump(CONFIG, f, indent=1)
        self.docker = Docker()
        for p in (mock.patch.object(ss, "DIR", d),
                  mock.patch.object(ss, "CREDENTIALS", os.path.join(d, "secrets", "bits-store.env")),
                  mock.patch.object(ss, "config_path", lambda: self.cfg),
                  mock.patch.object(ss.unlocking, "_compose", self.docker)):
            p.start()
            self.addCleanup(p.stop)

    def tearDown(self):
        self.tmp.cleanup()

    def test_collect_names_keys_never_values(self):
        with open(ss.CREDENTIALS, "w") as f:
            f.write("BITS_STORE_V_AK=akid\nBITS_STORE_V_SK=secret-value\n")
        got = ss.collect()
        self.assertEqual((got["config"], got["credentials"], got["console_key"]),
                         (CONFIG, ["BITS_STORE_V_AK", "BITS_STORE_V_SK"], "B" * 43))
        self.assertNotIn("secret-value", json.dumps(got))
        self.docker.pubkey = (1, "", "no such service")
        self.assertIsNone(ss.collect()["console_key"])

    def test_plan_then_apply(self):
        new = json.loads(json.dumps(CONFIG))
        new["bindings"].append({"prefix": "/sources", "volume": "v", "key_prefix": "SOURCES"})
        p = ss.plan(new, {"BITS_STORE_V_AK": "akid", "BITS_STORE_V_SK": "secret-value"})
        self.assertEqual((p["credentials"], p["restart"]), ({"BITS_STORE_V_AK": "will set", "BITS_STORE_V_SK": "will set"}, True))
        self.assertTrue(any("/sources" in ln for ln in p["diff"]))
        args, _, env = self.docker.calls[-1]
        self.assertEqual(self.docker.seen, new)                       # bits-store checked the new one
        self.assertIn("-e", args)
        self.assertNotIn("secret-value", " ".join(args))               # keys only in the environment
        self.assertEqual(env["BITS_STORE_V_SK"], "secret-value")
        self.assertNotIn("secret-value", json.dumps(p))
        done = ss.apply(new, {"BITS_STORE_V_AK": "akid", "BITS_STORE_V_SK": "secret-value"}, p["base"])
        self.assertEqual((done["written"], done["credentials"], done["restart"]), (True, ["BITS_STORE_V_AK", "BITS_STORE_V_SK"], True))
        self.assertEqual(json.load(open(self.cfg)), new)
        self.assertEqual(stat.S_IMODE(os.stat(self.cfg).st_mode), 0o644)
        self.assertEqual(stat.S_IMODE(os.stat(ss.CREDENTIALS).st_mode), 0o600)
        self.assertEqual(open(ss.CREDENTIALS).read(), "BITS_STORE_V_AK='akid'\nBITS_STORE_V_SK='secret-value'\n")
        self.assertTrue(done["backup"].startswith("config.json.bak-"))
        self.assertEqual([n for n in os.listdir(os.path.dirname(self.cfg)) if n.startswith("check-")], [])
        with self.assertRaisesRegex(ss.Refused, "changed since the plan"):
            ss.apply(new, {}, p["base"])

    def test_only_the_stores_key_names_reach_docker(self):
        for name in ("DOCKER_HOST", "BITS_STORE_PORT", "PATH"):      # compose's, or root's environment
            bad = json.loads(json.dumps(CONFIG))
            bad["volumes"]["v"]["access_key_env"] = name
            with self.assertRaisesRegex(ss.Refused, "key name", msg=name):
                ss.plan(bad, {name: "x"})
        with self.assertRaisesRegex(ss.Refused, "not a key name the volumes name"):
            ss.plan(CONFIG, {"BITS_STORE_OTHER": "x"})
        with open(ss.CREDENTIALS, "w") as f:                           # hand-added lines stay out
            f.write("DOCKER_HOST=tcp://elsewhere\nBITS_STORE_OTHER=o\nBITS_STORE_V_AK=a\n")
        ss.plan(CONFIG, {"BITS_STORE_V_SK": "s"})
        env = self.docker.calls[-1][2]
        self.assertEqual((env.get("BITS_STORE_V_AK"), env.get("DOCKER_HOST"), env.get("BITS_STORE_OTHER")),
                         ("a", os.environ.get("DOCKER_HOST"), None))

    def test_a_value_is_kept_as_typed(self):
        odd = "ab$cd #ef  "
        p = ss.plan(CONFIG, {"BITS_STORE_V_AK": "a", "BITS_STORE_V_SK": odd})
        ss.apply(CONFIG, {"BITS_STORE_V_AK": "a", "BITS_STORE_V_SK": odd}, p["base"])
        self.assertEqual(ss._credentials()["BITS_STORE_V_SK"], odd)
        with self.assertRaisesRegex(ss.Refused, "no '"):
            ss.plan(CONFIG, {"BITS_STORE_V_SK": "it's"})

    def test_the_config_directory_stays_in_the_checkout(self):
        for d in ("/etc", "../elsewhere"):
            with mock.patch.object(ss.unlocking, "_env_file", lambda: {"BITS_STORE_CONFIG_DIR": d}):
                with self.assertRaisesRegex(ss.Refused, "inside"):
                    REAL_CONFIG_PATH()

    def test_removed_key_is_checked_as_empty(self):
        with open(ss.CREDENTIALS, "w") as f:
            f.write("BITS_STORE_V_AK=akid\nBITS_STORE_V_SK=s\n")
        p = ss.plan(CONFIG, {"BITS_STORE_V_SK": ""})
        self.assertEqual(p["credentials"], {"BITS_STORE_V_SK": "will remove"})
        args = self.docker.calls[-1][0]
        self.assertIn("BITS_STORE_V_SK=", args)                                   # not the env_file's old one
        self.assertIn("BITS_STORE_V_AK", args)

    def test_refusals_write_nothing(self):
        before = open(self.cfg).read()
        self.docker.check = (1, "", 'binding "/x": no volume "nowhere"\n')
        with self.assertRaisesRegex(ss.Refused, 'bits-store refuses it: binding "/x": no volume'):
            ss.plan(CONFIG)
        base = ss.collect()["base"]
        with self.assertRaises(ss.Refused):
            ss.apply(CONFIG, {}, base)
        for bad in ([], "x"):
            with self.assertRaises(ss.Refused):
                ss.plan(bad)
        for creds in ({"lower": "x"}, {"BITS_STORE_V_AK": "two\nlines"}, ["BITS_STORE_V_AK"]):
            with self.assertRaises(ss.Refused, msg=creds):
                ss.plan(CONFIG, creds)
        self.assertEqual(open(self.cfg).read(), before)
        self.assertFalse(os.path.exists(ss.CREDENTIALS))


if __name__ == "__main__":
    unittest.main()
