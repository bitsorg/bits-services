# SPDX-FileCopyrightText: 2026 CERN
# SPDX-License-Identifier: GPL-3.0-or-later
"""python3 -m unittest -v test_scanner   (standard library only; a fake grype)"""

import json
import os
import shutil
import stat
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from unittest.mock import patch

import scanner

SBOM = {"bomFormat": "CycloneDX", "specVersion": "1.6", "components": [
    {"bom-ref": "curl@aaaa", "name": "curl", "version": "8.0.0"},
    {"bom-ref": "zlib@bbbb", "name": "zlib", "version": "1.3"},
    {"bom-ref": "ROOT@cccc", "name": "ROOT", "version": "6.30.00"}],
    "dependencies": [{"ref": "ROOT@cccc", "dependsOn": ["curl@aaaa", "zlib@bbbb"]}]}


def match(vid, ref, severity, cvss=None, fix=None, related=None):
    return {"artifact": {"id": ref},
            "vulnerability": {"id": vid, "severity": severity, "namespace": "nvd:cpe",
                              "dataSource": "https://nvd.nist.gov/vuln/detail/" + vid,
                              "description": "about " + vid, "urls": ["https://x/" + vid],
                              "cvss": cvss or [], "fix": {"versions": fix or []}},
            "relatedVulnerabilities": related or []}


MATCHES = [
    match("CVE-1", "curl@aaaa", "Critical", fix=["8.1.0"],
          cvss=[{"version": "3.1", "vector": "CVSS:3.1/AV:N", "metrics": {"baseScore": 9.8}}]),
    match("CVE-1", "zlib@bbbb", "Critical"),            # one advisory, two packages
    match("CVE-2", "curl@aaaa", "Negligible"),
    match("GHSA-3", "gone@dddd", "High"),               # not a component of this SBOM
]

FAKE = r'''#!/usr/bin/env python3
import json, os, sys
a = sys.argv[1:]
state = os.environ["FAKE_STATE"]
if a[:2] == ["db", "status"]:
    ok = os.path.exists(state)
    print(json.dumps({"valid": ok, "built": "2026-10-23T06:30:15Z" if ok else "",
                      "schemaVersion": "v6.1.10"}))
    sys.exit(0 if ok else 1)
if a[:2] == ["db", "update"]:
    if os.environ.get("FAKE_UPDATE_FAILS"):
        sys.exit("network unreachable")
    open(state, "w").close()
    sys.exit(0)
if a and a[0].startswith("sbom:"):
    assert os.environ["GRYPE_DB_AUTO_UPDATE"] == "false"
    json.load(open(a[0][5:]))
    print(open(os.environ["FAKE_MATCHES"]).read())
    sys.exit(0)
sys.exit("unexpected " + " ".join(a))
'''


class ScannerTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.dir, True)
        grype = os.path.join(self.dir, "grype")
        with open(grype, "w") as f:
            f.write(FAKE)
        os.chmod(grype, stat.S_IRWXU)
        with open(os.path.join(self.dir, "matches.json"), "w") as f:
            json.dump({"matches": MATCHES}, f)
        env = {"FAKE_STATE": os.path.join(self.dir, "db"),
               "FAKE_MATCHES": os.path.join(self.dir, "matches.json")}
        for p in (patch.dict(os.environ, env), patch.object(scanner, "GRYPE", grype),
                  patch.dict(scanner._db, {"status": None, "updating": False})):
            p.start()
            self.addCleanup(p.stop)

    def test_annotate_names_the_sboms_own_components(self):
        out, summary = scanner.annotate(SBOM, MATCHES)
        self.assertEqual(out["components"], SBOM["components"])        # otherwise unchanged
        self.assertEqual(out["dependencies"], SBOM["dependencies"])
        v = {x["id"]: x for x in out["vulnerabilities"]}
        self.assertEqual(sorted(v), ["CVE-1", "CVE-2"])
        self.assertEqual(v["CVE-1"]["affects"], [{"ref": "curl@aaaa"}, {"ref": "zlib@bbbb"}])
        self.assertEqual(v["CVE-1"]["ratings"], [{"severity": "critical", "method": "CVSSv31",
                                                  "score": 9.8, "vector": "CVSS:3.1/AV:N"}])
        self.assertEqual(v["CVE-1"]["recommendation"], "Fixed in 8.1.0.")
        self.assertEqual(v["CVE-2"]["ratings"], [{"severity": "info", "method": "other"}])
        self.assertEqual(summary, {"critical": 2, "high": 0, "medium": 0, "low": 0, "other": 1,
                                   "packages": 2, "vulnerabilities": 2})

    def test_related_cvss_are_kept_once(self):
        c = {"version": "3.1", "vector": "CVSS:3.1/AV:L", "metrics": {"baseScore": 5.5}}
        m = match("GHSA-1", "curl@aaaa", "Medium", cvss=[c],
                  related=[{"cvss": [dict(c, source="nvd@nist.gov"),
                                     {"version": "2.0", "vector": "AV:L", "metrics": {"baseScore": 2.1}}]}])
        out, _ = scanner.annotate(SBOM, [m])
        self.assertEqual([r["method"] for r in out["vulnerabilities"][0]["ratings"]], ["CVSSv31", "CVSSv2"])

    def test_no_database_no_scan_until_an_update_loads_one(self):
        with self.assertRaisesRegex(scanner.Busy, "no vulnerability database"):
            scanner.scan(json.dumps(SBOM).encode())
        with patch.dict(os.environ, {"FAKE_UPDATE_FAILS": "1"}):
            scanner.update_db()
        self.assertIsNone(scanner._db["status"])
        scanner.update_db()
        self.assertEqual(scanner._db["status"]["built"], "2026-10-23T06:30:15Z")
        out, summary = scanner.scan(json.dumps(SBOM).encode())
        self.assertEqual(summary["critical"], 2)

    def test_an_update_says_so_while_it_runs(self):
        seen = []
        real = scanner._grype
        with patch.object(scanner, "_grype", lambda a, t: seen.append(scanner._db["updating"]) or real(a, t)):
            scanner.update_db()
        self.assertEqual(seen, [True, True])                  # db update, then db status
        self.assertFalse(scanner._db["updating"])

    def test_not_cyclonedx_is_refused(self):
        for body in (b"nope", b"[]", json.dumps({"spdxVersion": "SPDX-2.3"}).encode()):
            with self.assertRaises(scanner.Refused):
                scanner.scan(body)

    def test_a_busy_scanner_says_so(self):
        scanner.update_db()
        with patch.object(scanner, "BUSY_WAIT_S", 0.01):
            scanner._work.acquire()
            try:
                with self.assertRaisesRegex(scanner.Busy, "busy"):
                    scanner.scan(json.dumps(SBOM).encode())
            finally:
                scanner._work.release()

    def test_http(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), scanner.Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        self.addCleanup(server.shutdown)
        base = "http://127.0.0.1:%d" % server.server_address[1]

        def call(path, body=None):
            req = urllib.request.Request(base + path, data=body)
            try:
                with urllib.request.urlopen(req, timeout=10) as r:
                    return r.status, json.loads(r.read())
            except urllib.error.HTTPError as e:
                return e.code, json.loads(e.read())
        self.assertEqual(call("/healthz")[0], 503)
        self.assertEqual(call("/v1/scan", json.dumps(SBOM).encode())[0], 503)
        scanner.update_db()
        self.assertEqual(call("/healthz")[0], 200)
        self.assertEqual(call("/v1/status")[1]["db"]["built"], "2026-10-23T06:30:15Z")
        self.assertFalse(call("/v1/status")[1]["updating"])
        status, res = call("/v1/scan", json.dumps(SBOM).encode())
        self.assertEqual((status, res["summary"]["packages"]), (200, 2))
        self.assertEqual(len(res["sbom"]["vulnerabilities"]), 2)
        self.assertEqual(call("/v1/scan", b"x")[0], 400)
        self.assertEqual(call("/nowhere")[0], 404)


if __name__ == "__main__":
    unittest.main()
