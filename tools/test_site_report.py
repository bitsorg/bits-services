# SPDX-License-Identifier: Apache-2.0
"""Tests for site_report.py: python3 -m unittest discover -s tools -p 'test_*.py'"""

import json
import os
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_report as rep  # noqa: E402

ENV = """GITLAB_API_URL='https://gitlab.cern.ch/api/v4'
BITS_FRONTEND_ORIGIN='https://bits-console.web.cern.ch'
BITS_OIDC_LOGIN_REDIRECT='https://bits.cern.ch/auth/callback'
BITS_FORGE_PROJECT='232657'
BITS_ORCH_PREPUB_URLS='http://cvmfs-bits-01.cern.ch:8080,http://bits-build-01.cern.ch:8080'
BITS_GITHUB_TOKEN='ghp_secret_value'
"""
ROUTE = {"name": "gitlab-read", "upstream": "https://gitlab.cern.ch",
         "inject_headers": {"PRIVATE-TOKEN": {"ingest": "gitlab-read"}}}
S3 = {"name": "s3", "upstream": "https://s3.cern.ch",
      "s3": {"buckets": {"b": {"access_key": {"ingest": "s3-access-b"},
                               "secret_key": {"ingest": "s3-secret-b"}}}}}
SCRAPE = """scrape_configs:
  - job_name: 'prepub'
    static_configs:
      - targets: ['cvmfs-bits-01.cern.ch:8080', 'bits-build-01.cern.ch:8080']
"""
UI = """gitlab_url: "https://gitlab.cern.ch"
project_id: "232657"
ops_backend_url: "https://bits.cern.ch"
"""
CONSOLE = """prepub_services:
  - "cvmfs-bits-01|http://cvmfs-bits-01.cern.ch:8080"
  - "bits-build-01|http://bits-build-01.cern.ch:8080"
"""


def write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


class SiteReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.services, self.console = (os.path.join(self.tmp.name, d) for d in ("services", "console"))
        write(os.path.join(self.services, ".env"), ENV)
        write(os.path.join(self.services, "config", "credentials-proxy", "config.json"),
              json.dumps({"routes": [ROUTE]}))
        write(os.path.join(self.services, "config", "store-writer", "config.json"),
              json.dumps({"routes": [S3]}))
        write(os.path.join(self.services, "monitoring", "scrape.yml"), SCRAPE)
        write(os.path.join(self.console, "communities", "LHCb", "ui-config.yaml"), UI)
        write(os.path.join(self.console, "config", "console.yaml"), CONSOLE)

    def tearDown(self):
        self.tmp.cleanup()

    def run_report(self, gitlab=None, slots=None):
        r, wanted, prepub = rep.Report(), set(), set()
        env = rep.sp.parse_env(rep.sp._read(os.path.join(self.services, ".env")))
        facts = rep.check_env(r, env)
        rep._run(r, "proxy configs", lambda: rep.proxy_slots(r, self.services, env, facts, wanted))
        if slots is not None:
            out = subprocess.CompletedProcess([], 0, stdout="\n".join(slots))
            rep.check_slots(r, self.services, wanted, run=lambda *a, **k: out)
        rep._run(r, "console", lambda: rep.check_console(r, self.console, facts, env, self.services, prepub))
        if gitlab is not None:
            rep.check_gitlab(r, facts, prepub, lambda path: gitlab[path.rsplit("/", 1)[-1]])
        return r

    def problems(self, r):
        return [line for line in r.lines if not line.startswith(("==", "ok", "note"))]

    def test_consistent_site(self):
        r = self.run_report()
        self.assertEqual(self.problems(r), ["secret    BITS_GITHUB_TOKEN is in .env: move it to service secrets"])
        self.assertNotIn("ghp_secret_value", "\n".join(r.lines))
        self.assertIn("ok        slots asked for: gitlab-read, s3-access-b, s3-secret-b", r.lines)

    def test_copies_that_disagree(self):
        write(os.path.join(self.console, "communities", "ATLAS", "ui-config.yaml"),
              UI.replace("bits.cern.ch", "bits-old.cern.ch").replace("232657", "1"))
        write(os.path.join(self.services, "monitoring", "scrape.yml"), SCRAPE.replace(", 'bits-build-01.cern.ch:8080'", ""))
        problems = self.problems(self.run_report())
        self.assertIn("differs   communities/ATLAS/ui-config.yaml project_id: 1, the site 232657", problems)
        self.assertIn("differs   communities/ATLAS/ui-config.yaml ops_backend_url: https://bits-old.cern.ch, "
                      "the site https://bits.cern.ch", problems)
        self.assertIn("differs   prepub http://bits-build-01.cern.ch:8080: in config/console.yaml, "
                      "not scraped (scrape.yml)", problems)

    def test_slots(self):
        problems = self.problems(self.run_report(slots=["gitlab-read", "s3-access-b", "client-cert", "old"]))
        self.assertIn("missing   slot s3-secret-b: a proxy asks for it, none is stored", problems)

    def test_gitlab(self):
        variables = [
            {"key": "PREPUB_URL", "value": "http://elsewhere:8080", "protected": True, "masked": False},
            {"key": "BITS_ORCH_URL", "value": "https://bits.cern.ch/", "protected": True, "masked": False},
            {"key": "PREPUB_API_TOKEN", "value": "tok-secret-1", "protected": True, "masked": True},
            {"key": "BITS_STATUS_TOKEN", "value": "tok-secret-2", "protected": False, "masked": False},
            {"key": "CERTIFY_MANIFESTS_REMOTE", "value": "x", "protected": True, "masked": False},
            {"key": "PREPUB_API_TOKEN", "value": "tok-secret-3", "protected": True, "masked": False,
             "environment_scope": "staging"},
        ]
        schedules = [{"id": 7, "description": "nightly", "active": True}]
        r = self.run_report(gitlab={"variables": variables, "pipeline_schedules": schedules})
        problems, text = self.problems(r), "\n".join(r.lines)
        for line in ("missing   variable BITS_READ_TOKEN: not on the project (a group variable may give it)",
                     "policy    variable BITS_STATUS_TOKEN is not protected: fork pipelines can read it",
                     "unsafe    variable BITS_STATUS_TOKEN is a secret but not masked",
                     "obsolete  variable CERTIFY_MANIFESTS_REMOTE: no longer read once the console CI retires it",
                     "differs   PREPUB_URL http://elsewhere:8080 is not one of the console's prepub services",
                     "unsafe    variable PREPUB_API_TOKEN[staging] is a secret but not masked",
                     "obsolete  schedule 7 (nightly): the orchestrator runs the nightlies"):
            self.assertIn(line, problems)
        self.assertFalse([p for p in problems if "BITS_ORCH_URL" in p])  # a trailing slash is the same
        self.assertNotIn("tok-secret", text)

    def test_command_line(self):
        tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site_report.py")
        r = subprocess.run([sys.executable, tool, "--services", self.services, "--console", self.console],
                           capture_output=True, text=True)
        self.assertEqual(r.returncode, 1, r.stdout + r.stderr)  # the secret in .env
        self.assertIn("1 problem(s)", r.stdout)
        self.assertNotIn("ghp_secret_value", r.stdout + r.stderr)

    def test_malformed_secret_line_not_printed(self):
        tool = os.path.join(os.path.dirname(os.path.abspath(__file__)), "site_report.py")
        for line in ("PREPUB_API_TOKEN='glpat-abc' junk\n", "PREPUB_API_TOKEN=\"glpat-abc\n"):
            write(os.path.join(self.services, ".env"), ENV + line)
            r = subprocess.run([sys.executable, tool, "--services", self.services],
                               capture_output=True, text=True)
            self.assertNotIn("glpat-abc", r.stdout + r.stderr)

    def test_places_and_kinds(self):
        self.assertEqual(rep._place("https://prepub.example"), rep._place("prepub.example:443"))
        self.assertEqual(rep._place("https://GitLab.cern.ch/api/v4"), rep._place("https://gitlab.cern.ch"))
        self.assertEqual(rep._shown("https://u:p@s3.example/b"), "https://s3.example/b")
        write(os.path.join(self.console, "communities", "SHiP", "ui-config.yaml"), 'project_id: "group/console"\n')
        r = self.run_report()
        self.assertFalse([p for p in self.problems(r) if "SHiP" in p])
        self.assertTrue([n for n in r.lines if n.startswith("note") and "SHiP" in n])

    def test_malformed_inputs_keep_the_rest(self):
        write(os.path.join(self.services, "config", "credentials-proxy", "config.json"),
              json.dumps({"routes": ["x", {"name": "r", "upstream": "https://gitlab.cern.ch/api/v4",
                                            "a": {"ingest": ["bad"]}}]}))
        write(os.path.join(self.console, "config", "console.yaml"), 'prepub_services: "http://x:8080"\n')
        problems = self.problems(self.run_report())
        self.assertIn("error     %s: a route that is not a mapping"
                      % os.path.join(self.services, "./config/credentials-proxy", "config.json"), problems)
        self.assertIn("error     config/console.yaml prepub_services is not a list", problems)
        self.assertFalse([p for p in problems if "upstream" in p])  # a path is the same place

    def test_gitlab_errors_never_show_the_token(self):
        r = rep.Report()
        rep.gitlab_section(r, {"console_project": "1", "gitlab_url": "http://gitlab.example"}, set(), "tok")
        self.assertEqual(self.problems(r), ["error     needs BITS_FORGE_PROJECT and an https GitLab URL in .env"])
        facts = {"console_project": "1", "gitlab_url": "https://gitlab.invalid"}
        r = rep.Report()
        rep.gitlab_section(r, facts, set(), "glpat-a\nb")
        self.assertNotIn("glpat", "\n".join(r.lines))

        def fail(path):
            raise ValueError("Invalid header value 'glpat-leak'")
        real = rep.gitlab_fetch
        rep.gitlab_fetch = lambda api, token: fail
        try:
            r = rep.Report()
            rep.gitlab_section(r, facts, set(), "glpat-leak")
        finally:
            rep.gitlab_fetch = real
        self.assertEqual(self.problems(r), ["error     reading GitLab failed: ValueError"])

    def test_pages_and_no_redirect(self):
        pages = {"1": ([{"key": "A"}], "2"), "2": ([{"key": "B"}], "")}

        class Resp:
            def __init__(self, page):
                self.body, self.headers = pages[page][0], {"X-Next-Page": pages[page][1]}
            def __enter__(self):
                return self
            def __exit__(self, *a):
                return False
            def read(self, *a):
                return json.dumps(self.body).encode()

        class Opener:
            def open(self, req, timeout):
                return Resp(req.full_url.rsplit("page=", 1)[1])
        real = rep.urllib.request.build_opener
        rep.urllib.request.build_opener = lambda *h: Opener()
        try:
            items = rep.gitlab_fetch("https://g/api/v4", "t")("/projects/1/variables")
        finally:
            rep.urllib.request.build_opener = real
        self.assertEqual([i["key"] for i in items], ["A", "B"])
        self.assertIsNone(rep._NoRedirect().redirect_request(None, None, 302, "Found", {}, "https://evil/"))


if __name__ == "__main__":
    unittest.main()
