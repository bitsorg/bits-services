# SPDX-License-Identifier: Apache-2.0
"""Tests for site_settings.py."""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_settings  # noqa: E402

COMPOSE = """
services:
  override-only:
    ports: !reset []
  bits-console-backend:
    environment:
      GITLAB_API_URL: "${GITLAB_API_URL:-}"
      BITS_CATALOG_TTL: "${BITS_CATALOG_TTL:-300}"
      BITS_GITHUB_TOKEN: "${BITS_GITHUB_TOKEN:-}"
      BITS_CHAT_URL: "${BITS_CHAT_URL}"
      HOOK_URL: "${HOOK_URL:-}"
      MIRROR_URL: "${MIRROR_URL:-}"
      DB_PASSWORD: "${DB_PASSWORD:-bits}"
      EMPTY_IS_DEFAULT: "${EMPTY_IS_DEFAULT:-dflt}"
  victoriametrics:
    command: ["-retentionPeriod=${VM_RETENTION:-13}"]
    volumes:
      - ${MONITORING_DATA_DIR:-./data/monitoring}/vm:/data
volumes:
  data:
    name: "${DATA_VOLUME-bits-data}"
"""
EXAMPLE = """# header text, not a key's
# BITS_NOT_A_KEY_EXAMPLE is mentioned only

# ─── monitoring (Phase 4) ──────────────
# Host dir for VictoriaMetrics data.
# Retention in months.
MONITORING_DATA_DIR=./data/monitoring
VM_RETENTION=13

# ─── bits-console backend ──────────────
GITLAB_API_URL=https://gitlab.cern.ch/api/v4
# BITS_CHAT_URL=   (an Ollama, e.g. http://host.docker.internal:11434)
# Only about the catalog.
BITS_CATALOG_TTL=300
"""
ENV = """GITLAB_API_URL='https://gitlab.example.org/api/v4'
HOOK_URL='https://hooks.example.org/send?token=t0psecret'
MIRROR_URL='https://u:pa/ss@mirror.example.org'
EMPTY_IS_DEFAULT=''
BITS_OIDC_ISSUER='https://other.example.org'
BITS_GITHUB_TOKEN='ghp_secretvalue'
BITS_CHAT_URL='https://user:hunter2@chat.example.org/x'
VM_RETENTION='24'
"""


class SiteSettingsTest(unittest.TestCase):
    def collect(self, profile=None, env=ENV):
        d = tempfile.mkdtemp()
        paths = {}
        for name, text in (("env", env), ("compose", COMPOSE), ("example", EXAMPLE), ("profile", profile)):
            if text is not None:
                paths[name] = os.path.join(d, name)
                with open(paths[name], "w") as f:
                    f.write(text)
        return site_settings.collect(paths["env"], paths["compose"], paths["example"],
                                     paths.get("profile", os.path.join(d, "none")))

    def test_every_setting_once(self):
        got = {s["key"]: s for s in self.collect()["settings"]}
        self.assertEqual(got["VM_RETENTION"]["origin"], "set")
        self.assertEqual((got["VM_RETENTION"]["value"], got["VM_RETENTION"]["default"]), ("24", "13"))
        self.assertEqual(got["VM_RETENTION"]["services"], ["victoriametrics"])
        self.assertEqual(got["VM_RETENTION"]["section"], "monitoring (Phase 4)")
        self.assertEqual(got["VM_RETENTION"]["doc"], "Host dir for VictoriaMetrics data. Retention in months.")
        self.assertEqual(got["BITS_CATALOG_TTL"]["origin"], "default")
        self.assertEqual(got["GITLAB_API_URL"]["origin"], "derived")
        self.assertEqual(got["BITS_OIDC_ISSUER"]["origin"], "overridden")       # not gitlab_url
        self.assertEqual(got["BITS_OIDC_ISSUER"]["derived"], "https://gitlab.example.org")
        self.assertEqual(got["BITS_OIDC_JWKS_URL"]["origin"], "unset")          # derived, not in .env
        self.assertEqual(got["DATA_VOLUME"]["default"], "bits-data")
        self.assertEqual(got["BITS_CHAT_URL"]["doc"], "an Ollama, e.g. http://host.docker.internal:11434")
        self.assertNotIn("BITS_NOT_A_KEY_EXAMPLE", got)
        self.assertEqual(got["GITLAB_API_URL"]["doc"], "")                    # no comment of its own
        self.assertEqual(got["BITS_CATALOG_TTL"]["doc"], "Only about the catalog.")  # not BITS_CHAT_URL's

    def test_secrets_never(self):
        answer = self.collect()
        got = {s["key"]: s for s in answer["settings"]}
        self.assertEqual((got["BITS_GITHUB_TOKEN"]["secret"], got["BITS_GITHUB_TOKEN"]["set"],
                          got["BITS_GITHUB_TOKEN"]["value"]), (True, True, None))
        for key in ("BITS_CHAT_URL", "HOOK_URL", "MIRROR_URL"):  # credentials in them: withheld whole
            self.assertEqual((got[key]["origin"], got[key]["value"]), ("withheld", None), key)
        self.assertEqual(answer["withheld"], ["BITS_CHAT_URL", "HOOK_URL", "MIRROR_URL"])
        self.assertEqual(got["DB_PASSWORD"]["default"], None)  # a secret's default is no less one
        self.assertEqual(got["EMPTY_IS_DEFAULT"]["origin"], "default")  # X= with ${X:-d}: the default
        text = json.dumps(answer)
        for secret in ("ghp_secretvalue", "hunter2", "user:", "t0psecret", "pa/ss", '"bits"'):
            self.assertNotIn(secret, text)
        self.assertNotIn("BITS_CHAT_URL", answer["profile"]["env"])  # left out, not half-redacted
        self.assertEqual(answer["facts"], {"gitlab_url": "https://gitlab.example.org"})

    def test_credentials_never_become_facts(self):
        answer = self.collect(env="GITLAB_API_URL='https://oauth2:glpat-XXXX@gitlab.example.org/api/v4'\n")
        self.assertNotIn("glpat", json.dumps(answer))
        self.assertEqual(answer["facts"], {})

    def test_the_profile_file_compared(self):
        answer = self.collect(profile="facts: {gitlab_url: 'https://gitlab.example.org'}")
        self.assertTrue(any("BITS_OIDC_ISSUER" in d for d in answer["profile_file"]["diffs"]))
        self.assertIn("secret in .env: BITS_GITHUB_TOKEN (move it to service secrets)",
                      answer["profile_file"]["notes"])
        self.assertNotIn("hunter2", json.dumps(answer))
        self.assertIn("error", self.collect(profile="facts: [")["profile_file"])
        self.assertIn("error", self.collect(profile="")["profile_file"])     # an empty file
        self.assertIn("error", self.collect(profile="- a list")["profile_file"])
        self.assertNotIn("profile_file", self.collect())


if __name__ == "__main__":
    unittest.main()
