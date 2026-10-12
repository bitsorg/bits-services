# SPDX-FileCopyrightText: 2026 CERN
# SPDX-License-Identifier: GPL-3.0-or-later
"""python3 -m unittest -v test_auditlog   (standard library only)"""

import json
import os
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
import urllib.error
import urllib.request

import auditlog

# The shared test vector: the orchestrator's tests (test_orch_outside.py) check
# the same two hashes with console_backend.orch.events._digest.
VECTOR = [
    ({"seq": 1, "ts_ms": 1760000000000, "kind": "worker.started", "subject": "worker",
      "actor_kind": "worker", "actor_id": "orchestrator", "cause": None,
      "payload": '{"schema":5,"note":"é"}'},
     "d8e5ed955e51314b180e89473c75025f3b81370fe49e9df3a8ce0d4b826fb264"),
    ({"seq": 2, "ts_ms": 1760000000001, "kind": "shadow.match", "subject": "certification:7",
      "actor_kind": "worker", "actor_id": "orchestrator", "cause": "action:3", "payload": "{}"},
     "1790c4478017c426a5d33654235a2a38f36a4eb22dacf545d9aec3b84c9db2e0"),
]


def chain(n, start=None):
    prev, rows = auditlog.GENESIS, []
    for i in range(1, n + 1):
        r = {"seq": i, "ts_ms": 1000 + i, "kind": "k", "subject": "s", "actor_kind": "worker",
             "actor_id": "orchestrator", "cause": None, "payload": json.dumps({"i": i})}
        r["prev_hash"] = prev
        r["hash"] = prev = auditlog.digest(prev, r)
        rows.append(r)
    return rows


class TestDigest(unittest.TestCase):
    def test_vector(self):
        prev = auditlog.GENESIS
        for row, want in VECTOR:
            self.assertEqual(auditlog.digest(prev, row), want)
            prev = want


class TestLog(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.log = auditlog.Log(self.dir)

    def test_append_and_reload(self):
        rows = chain(5)
        self.assertEqual(self.log.append(rows[:3]), 3)
        self.assertEqual(self.log.append(rows[2:]), 2)       # an identical resend is fine
        self.assertEqual(self.log.head, (5, rows[-1]["hash"]))
        again = auditlog.Log(self.dir)
        self.assertEqual(again.head, (5, rows[-1]["hash"]))
        self.assertEqual(again.after(3, 10), rows[3:])

    def test_refuses_gaps_forks_and_bad_hashes(self):
        rows = chain(4)
        self.log.append(rows[:2])
        with self.assertRaises(auditlog.Refused):
            self.log.append(rows[3:])                          # gap
        fork = dict(rows[1], payload='{"i":99}')
        with self.assertRaises(auditlog.Refused):
            self.log.append([fork])                            # differs from the one held
        bad = dict(rows[2], hash="0" * 64)
        with self.assertRaises(auditlog.Refused):
            self.log.append([bad])                             # hash not of its content
        relinked = dict(rows[2], prev_hash="1" * 64)
        relinked["hash"] = auditlog.digest(relinked["prev_hash"], relinked)
        with self.assertRaises(auditlog.Refused):
            self.log.append([relinked])                        # does not link
        with self.assertRaises(auditlog.Refused):
            self.log.append([dict(rows[2], extra=1)])
        self.assertEqual(self.log.head[0], 2)

    def test_a_failed_write_leaves_the_file_whole(self):
        rows = chain(3)
        self.log.append(rows[:1])
        size = os.path.getsize(self.log.path)
        real = os.fsync
        os.fsync = lambda fd: (_ for _ in ()).throw(OSError(28, "No space left on device"))
        try:
            with self.assertRaises(OSError):
                self.log.append(rows[1:])
        finally:
            os.fsync = real
        self.assertEqual((os.path.getsize(self.log.path), self.log.head[0]), (size, 1))
        self.assertEqual(self.log.append(rows[1:]), 2)
        self.assertEqual(auditlog.Log(self.dir).head[0], 3)

    def test_cut_last_line_is_dropped_and_broken_chain_refuses_to_start(self):
        rows = chain(3)
        self.log.append(rows)
        with open(self.log.path, "ab") as fh:
            fh.write(b'{"seq": 4, "ts')
        again = auditlog.Log(self.dir)
        self.assertEqual(again.head[0], 3)
        lines = open(self.log.path).read().splitlines()
        lines[1] = json.dumps(dict(json.loads(lines[1]), payload='{"i":7}'))
        with open(self.log.path, "w") as fh:
            fh.write("\n".join(lines) + "\n")
        with self.assertRaises(SystemExit):
            auditlog.Log(self.dir)


class TestHTTP(unittest.TestCase):
    def setUp(self):
        self.srv = auditlog.make_server(tempfile.mkdtemp(), "127.0.0.1:0", "w-token", "r-token")
        self.url = "http://127.0.0.1:%d" % self.srv.server_address[1]
        threading.Thread(target=self.srv.serve_forever, daemon=True).start()

    def tearDown(self):
        self.srv.shutdown()
        self.srv.server_close()

    def call(self, method, path, token, body=None):
        req = urllib.request.Request(self.url + path, method=method,
                                     data=json.dumps(body).encode() if body is not None else None,
                                     headers={"Authorization": "Bearer " + token,
                                              "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def test_flow(self):
        rows = chain(3)
        self.assertEqual(self.call("POST", "/v1/events", "r-token", {"events": rows})[0], 401)
        st, out = self.call("POST", "/v1/events", "w-token", {"events": rows})
        self.assertEqual((st, out["accepted"], out["head"]["seq"]), (200, 3, 3))
        st, out = self.call("GET", "/v1/head", "r-token")
        self.assertEqual((st, out["hash"]), (200, rows[-1]["hash"]))
        st, out = self.call("GET", "/v1/events?after=1&limit=1", "r-token")
        self.assertEqual(out["events"], rows[1:2])
        st, out = self.call("POST", "/v1/events", "w-token", {"events": [dict(rows[0], kind="x")]})
        self.assertEqual((st, out["head"]["seq"]), (409, 3))
        self.assertEqual(self.call("GET", "/v1/head", "nope")[0], 401)


@unittest.skipUnless(shutil.which("openssl"), "needs openssl to make a certificate")
class TestTLS(unittest.TestCase):
    def test_a_silent_client_does_not_block_the_others(self):
        d = tempfile.mkdtemp()
        cert, key = os.path.join(d, "c.pem"), os.path.join(d, "k.pem")
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj",
                        "/CN=localhost", "-keyout", key, "-out", cert, "-days", "1"],
                       check=True, capture_output=True)
        srv = auditlog.make_server(os.path.join(d, "data"), "127.0.0.1:0", "w", cert=cert, key=key)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.server_close)
        self.addCleanup(srv.shutdown)
        port = srv.server_address[1]
        idle = socket.create_connection(("127.0.0.1", port))
        self.addCleanup(idle.close)
        ctx = ssl.create_default_context()
        ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
        req = urllib.request.Request("https://127.0.0.1:%d/v1/head" % port,
                                     headers={"Authorization": "Bearer w"})
        with urllib.request.urlopen(req, timeout=5, context=ctx) as r:
            self.assertEqual(json.load(r)["seq"], 0)


if __name__ == "__main__":
    unittest.main()
