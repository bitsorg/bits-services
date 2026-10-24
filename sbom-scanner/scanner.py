#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 CERN
# SPDX-License-Identifier: GPL-3.0-or-later
"""sbom-scanner: a CycloneDX SBOM in, the same SBOM with its vulnerabilities out.

The bits orchestrator's worker POSTs each published build's sbom.cdx.json. grype
matches its components (their purls and CPEs) with its vulnerability database,
and the SBOM comes back unchanged but for a CycloneDX `vulnerabilities` section
whose `affects` name the SBOM's own bom-refs (with the fixing versions as
`unaffected`), so viewers can show them on the dependency graph; grype's risk,
EPSS and KEV are grype:* properties. The service holds no secret; its only
traffic out is grype's database download, refreshed every
SCANNER_DB_REFRESH_HOURS. One scan or update runs at a time.

    POST /v1/scan   a CycloneDX JSON document (at most 32 MB)
                    -> {"db": {"built", "schema"}, "summary": {...}, "sbom": {...}}
    GET  /v1/status {"db": {"built", "schema"} or null, "updating", "grype": version}
    GET  /healthz   200 once a database is loaded, else 503

Python standard library and the grype binary. Environment:

    SCANNER_LISTEN            host:port (default 0.0.0.0:8080)
    SCANNER_DB_REFRESH_HOURS  default 6
    SCANNER_GRYPE             the grype binary (default grype)
    GRYPE_DB_CACHE_DIR        where grype keeps its database (a volume)
    TMPDIR                    grype's download and unpacking (on the volume, not tmpfs)
"""

import json
import logging
import os
import subprocess
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MAX_BODY = 32 << 20
SCAN_TIMEOUT_S = 45             # below the worker's 60 s read timeout
UPDATE_TIMEOUT_S = 1800
BUSY_WAIT_S = 5
GRYPE = os.environ.get("SCANNER_GRYPE", "grype")
# grype's severities, as CycloneDX names them.
SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low",
            "negligible": "info", "unknown": "unknown"}
SUMMARY = ("critical", "high", "medium", "low")
CVSS_METHOD = {"2.0": "CVSSv2", "3.0": "CVSSv3", "3.1": "CVSSv31", "4.0": "CVSSv4"}

log = logging.getLogger("sbom-scanner")
_work = threading.Lock()          # one scan or database update at a time
_db = {"status": None, "updating": False}


class Refused(Exception):
    """The request's fault (400)."""


class Busy(Exception):
    """No slot within BUSY_WAIT_S (503)."""


def _grype(args, timeout):
    env = dict(os.environ, GRYPE_DB_AUTO_UPDATE="false", GRYPE_CHECK_FOR_APP_UPDATE="false")
    return subprocess.run([GRYPE] + args, capture_output=True, text=True, timeout=timeout,
                          env=env, check=False)


def db_status():
    """{"built", "schema"} of the loaded database, or None."""
    p = _grype(["db", "status", "-o", "json"], 60)
    try:
        d = json.loads(p.stdout or "{}")
    except ValueError:
        return None
    if p.returncode != 0 or not d.get("valid"):
        return None
    return {"built": d.get("built", ""), "schema": d.get("schemaVersion", "")}


def update_db():
    """Fetch a newer database, if there is one; keeps the old one on failure.
    Meanwhile /v1/status says `updating`, so the worker does not wait on scans."""
    _db["updating"] = True
    try:
        with _work:
            p = _grype(["db", "update"], UPDATE_TIMEOUT_S)
            if p.returncode != 0:
                log.warning("grype db update: %s", (p.stderr or p.stdout).strip()[-300:])
            _db["status"] = db_status()
    finally:
        _db["updating"] = False
    log.info("vulnerability database: %s", _db["status"])


def _ratings(v, severity):
    """CycloneDX ratings from grype's CVSS records, the advisory's own first."""
    out, seen = [], set()
    for c in list(v.get("vulnerability", {}).get("cvss") or []) + [
            c for r in v.get("relatedVulnerabilities") or [] for c in r.get("cvss") or []]:
        key = (c.get("version"), c.get("vector"))
        if key in seen:
            continue
        seen.add(key)
        r = {"severity": severity, "method": CVSS_METHOD.get(str(c.get("version")), "other")}
        score = (c.get("metrics") or {}).get("baseScore")
        if score is not None:
            r["score"] = score
        if c.get("vector"):
            r["vector"] = c["vector"]
        if c.get("source"):
            r["source"] = {"name": c["source"]}
        out.append(r)
    return out or [{"severity": severity, "method": "other"}]


def _threat(v):
    """grype's risk score, the highest EPSS and the CISA KEV date of *v*, as properties."""
    epss = max([float(e.get("epss") or 0) for e in v.get("epss") or []] or [0])
    kev = [str(k.get("dateAdded") or "listed") for k in v.get("knownExploited") or []]
    return [{"name": k, "value": x} for k, x in (
        ("grype:risk", f"{float(v.get('risk') or 0):.2f}" if v.get("risk") else ""),
        ("grype:epss", f"{epss:.5f}" if epss else ""),
        ("grype:kev", min(kev) if kev else "")) if x]


def annotate(sbom, matches):
    """(*sbom* with a `vulnerabilities` section from grype's *matches*, summary).
    One entry per vulnerability, affecting every component it matched; each
    affected component lists the versions that fix it as `unaffected`."""
    refs = {c.get("bom-ref") for c in sbom.get("components") or [] if c.get("bom-ref")}
    vulns, order, hits = {}, [], set()
    for m in matches:
        ref = (m.get("artifact") or {}).get("id")
        v = m.get("vulnerability") or {}
        vid = v.get("id")
        if not vid or ref not in refs:
            continue
        severity = SEVERITY.get(str(v.get("severity", "unknown")).lower(), "unknown")
        if vid not in vulns:
            fix = (v.get("fix") or {}).get("versions") or []
            entry = {"bom-ref": "vuln-%s" % vid, "id": vid,
                     "source": {"name": v.get("namespace", ""), "url": v.get("dataSource", "")},
                     "ratings": _ratings(m, severity),
                     "description": (v.get("description") or "")[:4000],
                     "advisories": [{"url": u} for u in (v.get("urls") or [])[:20]],
                     "affects": []}
            if fix:
                entry["recommendation"] = "Fixed in %s." % ", ".join(fix)
            threat = _threat(v)
            if threat:
                entry["properties"] = threat
            vulns[vid] = entry
            order.append(vid)
        if ref not in {a["ref"] for a in vulns[vid]["affects"]}:
            fixed = [{"version": str(x), "status": "unaffected"}
                     for x in (v.get("fix") or {}).get("versions") or []]
            vulns[vid]["affects"].append(dict({"ref": ref}, **({"versions": fixed} if fixed else {})))
            hits.add((vid, ref, severity))
    out = dict(sbom, vulnerabilities=[vulns[i] for i in order])
    summary = {k: 0 for k in SUMMARY + ("other",)}
    for _vid, _ref, sev in hits:
        summary[sev if sev in SUMMARY else "other"] += 1
    summary["packages"] = len({ref for _v, ref, _s in hits})
    summary["vulnerabilities"] = len(order)
    return out, summary


def scan(body):
    """The scan of one CycloneDX document (bytes): (annotated sbom, summary)."""
    try:
        sbom = json.loads(body)
    except ValueError as e:
        raise Refused("not JSON: %s" % e)
    if not isinstance(sbom, dict) or sbom.get("bomFormat") != "CycloneDX":
        raise Refused("not a CycloneDX document")
    if not _work.acquire(timeout=BUSY_WAIT_S):
        raise Busy("the scanner is busy; try again shortly")
    try:
        if _db["status"] is None:
            raise Busy("no vulnerability database yet")
        with tempfile.TemporaryDirectory(prefix="scan-") as d:
            path = os.path.join(d, "sbom.cdx.json")
            with open(path, "wb") as f:
                f.write(body)
            p = _grype(["sbom:" + path, "-o", "json", "-q"], SCAN_TIMEOUT_S)
        if p.returncode != 0:
            raise RuntimeError("grype: %s" % (p.stderr or p.stdout).strip()[-300:])
        return annotate(sbom, json.loads(p.stdout).get("matches") or [])
    finally:
        _work.release()


class Handler(BaseHTTPRequestHandler):
    server_version = "sbom-scanner"

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def _send(self, status, obj, extra=None):
        body = json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/healthz":
            ok = _db["status"] is not None
            self._send(200 if ok else 503, {"ok": ok})
        elif self.path == "/v1/status":
            self._send(200, {"db": _db["status"], "updating": _db["updating"],
                             "grype": os.environ.get("GRYPE_VERSION", "")})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/v1/scan":
            return self._send(404, {"error": "not found"})
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = -1
        if n <= 0 or n > MAX_BODY:
            return self._send(413 if n > MAX_BODY else 400, {"error": "a body of 1 B to 32 MB"})
        body = self.rfile.read(n)
        t = time.monotonic()
        try:
            sbom, summary = scan(body)
        except Refused as e:
            return self._send(400, {"error": str(e)})
        except Busy as e:
            return self._send(503, {"error": str(e)}, {"Retry-After": "30"})
        except Exception as e:            # pylint: disable=broad-except
            log.warning("scan failed: %s", e)
            return self._send(500, {"error": str(e)[:300]})
        log.info("scanned %d components in %.1f s: %s", len(sbom.get("components") or []),
                 time.monotonic() - t, summary)
        self._send(200, {"db": _db["status"], "summary": summary, "sbom": sbom})


def _refresher(hours):
    while True:
        try:
            update_db()
        except Exception as e:            # pylint: disable=broad-except
            log.warning("database update failed: %s", e)
        time.sleep(max(hours, 0.1) * 3600)


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stderr,
                        format="%(asctime)s %(levelname)s %(message)s")
    host, _, port = os.environ.get("SCANNER_LISTEN", "0.0.0.0:8080").rpartition(":")
    if os.environ.get("TMPDIR"):          # grype unpacks its download here: the volume
        os.makedirs(os.environ["TMPDIR"], exist_ok=True)
    _db["status"] = db_status()           # a database from the volume serves at once
    threading.Thread(target=_refresher, args=(float(os.environ.get("SCANNER_DB_REFRESH_HOURS", "6")),),
                     daemon=True).start()
    ThreadingHTTPServer((host or "0.0.0.0", int(port)), Handler).serve_forever()


if __name__ == "__main__":
    main()
