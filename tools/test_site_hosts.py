# SPDX-License-Identifier: Apache-2.0
"""Tests for site_hosts.py, with docker compose stood in."""

import json
import os
import socket
import sys
import tempfile
import unittest
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_hosts  # noqa: E402

CONFIG = {
    "networks": {"audit-net": {"name": "x_audit-net", "internal": True}, "services-net": {"name": "x_services"}},
    "services": {
        "bits-console-backend": {
            "image": "bits-services/bits-console-backend:local",
            "ports": [{"mode": "ingress", "target": 8443, "published": "8443", "protocol": "tcp"}],
            "networks": {"services-net": None},
            "environment": {"GITLAB_API_URL": "https://gitlab.cern.ch/api/v4",
                            "BITS_ORCH_PREPUB_URLS": "http://cvmfs-bits-01.cern.ch:8080,http://bits-build-01.cern.ch:8080",
                            "BITS_CHAT_URL": "https://user:s3cret@chat.example.org/x?token=abc",
                            "BITS_SIGN_PROXY_TOKEN": "https://should-not-appear.example",
                            "BITS_MIRROR_URL": "https://tok/en@mirror.example,https://admin:9988?x@h.example",
                            "BITS_OTHER_URL": "https://[s3cr3t]/x",
                            "BITS_ORCH_QUEUE": "1"}},
        "victoriametrics": {"image": "victoriametrics/victoria-metrics:v1.99.0",
                            "ports": [{"host_ip": "127.0.0.1", "target": 8428, "published": "8428"}],
                            "networks": {"monitoring-net": None}},
        "audit-log": {"image": "bits-services/audit-log:local", "networks": {"audit-net": None}},
        "node-exporter": {"image": "prom/node-exporter", "networks": {"monitoring-net": None}},
        "bits-admin": {"image": "bits-services/bits-console-backend:local", "profiles": ["admin"],
                       "networks": {"admin-audit-net": None},
                       "environment": {"BITS_ADMIN_AUDIT_URL": "http://audit-log:8443"}},
    },
}
SCRAPE = """
scrape_configs:
  - job_name: 'node-exporter'
    static_configs:
      - targets: ['node-exporter:9100']
  - job_name: 'prepub'
    static_configs:
      - targets: ['cvmfs-bits-01.cern.ch:8080']
        labels: {role: publisher}
  - job_name: 'runner-nodes'
    http_sd_configs:
      - url: 'http://runner-sd:8080/'
"""


class SiteHostsTest(unittest.TestCase):
    def collect(self, scrape=SCRAPE, config=CONFIG, profiles="admin\nscanner\n"):
        calls = []

        def compose(args):
            calls.append(args)
            if args == ["config", "--profiles"]:
                return 0, profiles, ""
            return 0, json.dumps(config), ""
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False) as f:
            f.write(scrape)
        self.addCleanup(os.unlink, f.name)
        return site_hosts.collect(compose, {"bits-console-backend": "healthy"}, f.name, host="bits.cern.ch"), calls

    def test_services_ports_and_networks(self):
        got, calls = self.collect()
        self.assertEqual(calls[1], ["--profile", "admin", "--profile", "scanner", "config", "--format", "json"])
        backend = got["services"]["bits-console-backend"]
        self.assertEqual((backend["state"], backend["ports"], backend["networks"]),
                         ("healthy", [{"host_ip": "", "published": "8443", "target": 8443, "protocol": "tcp"}],
                          ["services-net"]))
        self.assertEqual(got["services"]["victoriametrics"]["ports"][0]["host_ip"], "127.0.0.1")
        self.assertEqual(got["services"]["bits-admin"]["state"], "not running")
        self.assertEqual(got["networks"], {"audit-net": True, "services-net": False})
        self.assertEqual(got["host"], "bits.cern.ch")

    def test_links_never_carry_a_secret(self):
        got, _ = self.collect()
        links = {(l["service"], l["key"], l["host"], l["port"]) for l in got["links"]}
        self.assertEqual(links, {
            ("bits-console-backend", "GITLAB_API_URL", "gitlab.cern.ch", 443),
            ("bits-console-backend", "BITS_ORCH_PREPUB_URLS", "cvmfs-bits-01.cern.ch", 8080),
            ("bits-console-backend", "BITS_ORCH_PREPUB_URLS", "bits-build-01.cern.ch", 8080),
            ("bits-admin", "BITS_ADMIN_AUDIT_URL", "audit-log", 8443)})
        text = json.dumps(got)
        for secret in ("s3cret", "token=abc", "should-not-appear", "/api/v4", "user:", "tok/en", "admin:9988", "9988",
                       "s3cr3t", "mirror.example", "chat.example"):
            self.assertNotIn(secret, text)

    def test_scrape_targets(self):
        got, _ = self.collect()
        self.assertEqual(got["scrape"], [
            {"job": "node-exporter", "host": "node-exporter", "port": 9100, "labels": {}},
            {"job": "prepub", "host": "cvmfs-bits-01.cern.ch", "port": 8080, "labels": {"role": "publisher"}}])
        self.assertEqual(self.collect(scrape="{not yaml: [")[0]["scrape"], [])

    def test_up_from_victoriametrics(self):
        answers = {
            "up": [{"metric": {"job": "prepub", "instance": "cvmfs-bits-01.cern.ch:8080"}, "value": [1, "1"]},
                   {"metric": {"job": "prepub", "instance": "bits-build-01.cern.ch:8080"}, "value": [1, "0"]}],
            "last_over_time(timestamp(up == 1)[1d])": [
                {"metric": {"job": "prepub", "instance": "bits-build-01.cern.ch:8080"}, "value": [1, "1762000000"]}]}
        asked = []

        def get(url):
            asked.append(url)
            query = urllib.parse.parse_qs(urllib.parse.urlsplit(url).query)["query"][0]
            return json.dumps({"data": {"result": answers[query]}}).encode()
        self.assertEqual(site_hosts.scrape_up(get), {"targets": [
            {"job": "prepub", "instance": "bits-build-01.cern.ch:8080", "up": 0, "last_up": 1762000000.0},
            {"job": "prepub", "instance": "cvmfs-bits-01.cern.ch:8080", "up": 1, "last_up": None}]})
        self.assertEqual(asked[0], site_hosts.VM_URL + "/api/v1/query?query=up")
        answers["up"].append({"metric": {"job": "x", "instance": "y"}, "value": [1, "NaN"]})
        answers["last_over_time(timestamp(up == 1)[1d])"][0]["value"] = [1, "+Inf"]
        got = site_hosts.scrape_up(get)["targets"]
        self.assertEqual([(t["instance"], t["last_up"]) for t in got],
                         [("bits-build-01.cern.ch:8080", None), ("cvmfs-bits-01.cern.ch:8080", None)])
        self.assertEqual(site_hosts.scrape_up(lambda url: (_ for _ in ()).throw(OSError("refused"))),
                         {"error": "VictoriaMetrics did not answer (OSError)"})
        self.assertIn("error", site_hosts.scrape_up(lambda url: b"<html>"))

    def test_what_check_probes(self):
        hosts, _ = self.collect()
        hosts["links"].append({"service": "x", "key": "BITS_OIDC_ISSUER", "scheme": "https",
                               "host": "gitlab.cern.ch", "port": 443})
        got = [(t, w) for t, w, _ in site_hosts.probes(hosts)]
        self.assertEqual(got, [
            ("127.0.0.1:8443", "GET /healthz"),
            ("cvmfs-bits-01.cern.ch:8080", "GET /api/v1/health"),   # a prepub node
            ("bits-build-01.cern.ch:8080", "GET /api/v1/health"),
            ("gitlab.cern.ch:443", "TCP connect"),                   # the first link to it decides
        ])                                  # audit-log, node-exporter: services here, not probed

    def test_check_says_only_the_outcome(self):
        hosts, _ = self.collect()
        real_tcp, real_http = site_hosts._tcp, site_hosts._http
        def http(url, **kw):
            if "cvmfs-bits-01" in url:
                raise OSError("HTTP 503")
            if "bits-build-01" in url:
                raise ConnectionRefusedError("[Errno 111] secret detail")
            return "HTTP 200"
        site_hosts._http = http
        site_hosts._tcp = lambda h, p, timeout=3: (_ for _ in ()).throw(socket.timeout())
        try:
            results = {r["target"]: (r["ok"], r["said"]) for r in site_hosts.check(hosts)}
        finally:
            site_hosts._tcp, site_hosts._http = real_tcp, real_http
        self.assertEqual(results, {"127.0.0.1:8443": (True, "HTTP 200"),
                                   "cvmfs-bits-01.cern.ch:8080": (False, "HTTP 503"),
                                   "bits-build-01.cern.ch:8080": (False, "refused"),
                                   "gitlab.cern.ch:443": (False, "no answer in 3 s")})

    def test_check_keeps_to_its_deadline_and_survives_odd_targets(self):
        import threading
        release = threading.Event()
        hosts = {"host": "bits", "services": {}, "links": [
            {"host": "slow.example", "port": 1, "key": ""}, {"host": "odd.example", "port": "${PORT}", "key": ""}]}
        real = site_hosts._tcp
        site_hosts._tcp = lambda h, p, timeout=3: release.wait(5) if h == "slow.example" else real(h, p)
        try:
            got = {r["target"]: r["said"] for r in site_hosts.check(hosts, deadline=0.5)}
        finally:
            release.set()
            site_hosts._tcp = real
        self.assertEqual(got, {"slow.example:1": "no answer in 0 s", "odd.example:${PORT}": "ValueError"})

    def test_a_redirect_is_the_answer(self):
        import http.server
        import threading
        srv = http.server.HTTPServer(("127.0.0.1", 0), type("H", (http.server.BaseHTTPRequestHandler,), {
            "do_GET": lambda s: (s.send_response(302), s.send_header("Location", "http://127.0.0.1:1/x"),
                                 s.end_headers()), "log_message": lambda *a: None}))
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        self.addCleanup(srv.shutdown)
        with self.assertRaises(OSError) as e:
            site_hosts._http("http://127.0.0.1:%d/api/v1/health" % srv.server_address[1])
        self.assertEqual(str(e.exception), "HTTP 302")

    def test_a_failing_config_is_an_error(self):
        with self.assertRaises(ValueError):
            site_hosts.collect(lambda args: (1, "", "boom"), {}, "/nonexistent")
        with self.assertRaises(ValueError):  # without --profiles, profiled services would vanish
            site_hosts.collect(lambda args: (1, "", "") if args == ["config", "--profiles"]
                               else (0, json.dumps(CONFIG), ""), {}, "/nonexistent")


if __name__ == "__main__":
    unittest.main()
