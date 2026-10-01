#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 CERN
# SPDX-License-Identifier: GPL-3.0-or-later
#
# runner-sd — a Prometheus http_sd endpoint for the GitLab runner fleet's
# node-exporters. cvmfs-vmagent GETs it (http_sd_configs); the target set is
# rebuilt from the GitLab Runners API, so a runner added or removed from the
# fleet is scraped / dropped automatically with NO edit to scrape.yml.
#
# Serves JSON at "/" in Prometheus http_sd format:
#   [ {"targets": ["<ip>:9100"], "labels": {"job":"node","instance":"<desc>"}}, … ]
#
# Env:
#   GITLAB_URL         e.g. https://gitlab.cern.ch                        (required)
#   RUNNER_SD_TOKEN    PRIVATE-TOKEN allowed to list runners and read their
#                      ip_address (project Maintainer/Owner, or admin)    (required)
#   PROJECT_ID         list THIS project's runners; empty => instance /runners/all (admin)
#   NODE_EXPORTER_PORT node-exporter port on each runner (default 9100)
#   ONLY_DESC_REGEX    optional: only runners whose description matches (e.g. '^bits-')
#   CACHE_TTL          seconds between GitLab refreshes (default 45)
#   LISTEN_PORT        default 8080
#
# Not configured (no URL/token) => serves []  (vmagent scrapes nothing, no error).
# Stdlib only — runs on python:alpine with no pip install.
import json, os, re, time, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

GITLAB_URL = os.environ.get("GITLAB_URL", "").rstrip("/")
TOKEN      = os.environ.get("RUNNER_SD_TOKEN", "").strip()
PROJECT_ID = os.environ.get("PROJECT_ID", "").strip()
NODE_PORT  = os.environ.get("NODE_EXPORTER_PORT", "9100").strip() or "9100"
CACHE_TTL  = int(os.environ.get("CACHE_TTL", "45"))
LISTEN     = int(os.environ.get("LISTEN_PORT", "8080"))
_DESC_RE   = re.compile(os.environ["ONLY_DESC_REGEX"]) if os.environ.get("ONLY_DESC_REGEX") else None

_cache = {"ts": 0.0, "body": b"[]"}


def _api(path):
    req = urllib.request.Request(GITLAB_URL + path, headers={"PRIVATE-TOKEN": TOKEN})
    with urllib.request.urlopen(req, timeout=10) as r:
        return json.load(r)


def build_targets():
    if not GITLAB_URL or not TOKEN:
        return []
    listing = (f"/api/v4/projects/{PROJECT_ID}/runners?status=online&per_page=100"
               if PROJECT_ID else "/api/v4/runners/all?status=online&per_page=100")
    runners = _api(listing)
    out, seen = [], set()
    for r in runners:
        desc = (r.get("description") or "").strip()
        if _DESC_RE and not _DESC_RE.search(desc):
            continue
        # ip_address is only on the per-runner detail endpoint.
        try:
            d = _api(f"/api/v4/runners/{r['id']}")
        except Exception:
            d = r
        ip = (d.get("ip_address") or "").strip()
        if not ip or ip in seen:
            continue
        seen.add(ip)
        out.append({
            "targets": [f"{ip}:{NODE_PORT}"],
            "labels": {"job": "node", "instance": desc or ip, "runner_id": str(r.get("id", ""))},
        })
    return out


def body():
    now = time.time()
    if now - _cache["ts"] > CACHE_TTL:
        try:
            targets = build_targets()
            _cache["body"] = json.dumps(targets).encode()
            _cache["ts"] = now
            print(f"runner-sd: {len(targets)} target(s)", flush=True)
        except Exception as e:  # keep serving the last good list
            print(f"runner-sd: refresh failed, serving cached: {e}", flush=True)
    return _cache["body"]


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        b = body()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def log_message(self, *a):  # quiet
        pass


if __name__ == "__main__":
    print(f"runner-sd: listening on :{LISTEN}  gitlab={GITLAB_URL or '(unset)'} "
          f"project={PROJECT_ID or 'instance/all'} configured={bool(GITLAB_URL and TOKEN)}",
          flush=True)
    ThreadingHTTPServer(("", LISTEN), Handler).serve_forever()
