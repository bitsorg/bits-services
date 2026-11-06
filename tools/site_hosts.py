#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""What bits-admin's Hosts page shows (ADR bits-services 0001, H): this host's services
with their ports and Docker networks, the hosts and ports they connect to, and the hosts
monitoring scrapes. Only names, hosts and ports: never a value of a secret.

    tools/site_hosts.py          # the JSON the host helper hands bits-admin
"""

import concurrent.futures
import json
import math
import os
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request
from urllib.parse import urlencode, urlsplit

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from site_profile import SECRET_NAME  # noqa: E402

DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
VM_URL = os.environ.get("BITS_ADMIN_HELPER_VM_URL", "http://127.0.0.1:8428")  # VictoriaMetrics, on the host
URL = re.compile(r"^(https?|s3|b3)://", re.I)
PORTS = {"http": 80, "https": 443, "s3": 443, "b3": 443}


def _endpoint(text):
    """{scheme, host, port} of a URL, without path or query; None if not one."""
    if not URL.match(text):
        return None
    try:
        u = urlsplit(text)
        port = u.port
    except ValueError:  # its text could quote the value
        return None
    if not u.hostname:
        return None
    return {"scheme": u.scheme.lower(), "host": u.hostname.lower(), "port": port or PORTS[u.scheme.lower()]}


def services_view(config, states):
    """{service: {...}} and {network: internal} from `docker compose config --format json`."""
    networks = {name: bool((n or {}).get("internal")) for name, n in (config.get("networks") or {}).items()}
    out = {}
    for name, s in sorted((config.get("services") or {}).items()):
        ports = [{"host_ip": p.get("host_ip") or "", "published": str(p.get("published") or ""),
                  "target": p.get("target"), "protocol": p.get("protocol") or "tcp"}
                 for p in s.get("ports") or [] if isinstance(p, dict)]
        out[name] = {"image": s.get("image") or "", "state": states.get(name, "not running"),
                     "ports": ports, "networks": sorted(s.get("networks") or {}),
                     "network_mode": s.get("network_mode") or "", "profiles": s.get("profiles") or []}
    return out, networks


def links_view(config):
    """[{service, key, scheme, host, port}]: where each service's settings point."""
    out = []
    for name, s in sorted((config.get("services") or {}).items()):
        env = s.get("environment") or {}
        for key, value in sorted(env.items() if isinstance(env, dict) else []):
            # "@": user and password, which a "/" or "," in them would make look like a host
            if SECRET_NAME.search(key) or not isinstance(value, str) or "@" in value:
                continue
            for part in value.split(","):
                end = _endpoint(part.strip())
                if end:
                    out.append(dict(end, service=name, key=key))
    return out


def scrape_view(text):
    """[{job, host, port, labels}] of the static targets in monitoring/scrape.yml."""
    out = []
    for job in (yaml.safe_load(text) or {}).get("scrape_configs") or []:
        for sc in job.get("static_configs") or []:
            for target in sc.get("targets") or []:
                host, _, port = str(target).rpartition(":")
                if host and port.isdigit():
                    out.append({"job": job.get("job_name", ""), "host": host.lower(), "port": int(port),
                                "labels": {k: str(v) for k, v in (sc.get("labels") or {}).items()}})
    return out


def _query(expr, get):
    data = get("%s/api/v1/query?%s" % (VM_URL, urlencode({"query": expr})))
    return json.loads(data)["data"]["result"]


def _get(url):
    with urllib.request.urlopen(url, timeout=3) as r:
        return r.read(1 << 20)


def scrape_up(get=_get):
    """{"targets": [{job, instance, up, last_up}]} from VictoriaMetrics' up, or {"error"}:
    up 1 or 0 now; last_up the time (s) it last answered in the past day, or None."""
    try:
        now = _query("up", get)
        last = {(r["metric"].get("job"), r["metric"].get("instance")): float(r["value"][1])
                for r in _query("last_over_time(timestamp(up == 1)[1d])", get)}
        targets = []
        for r in now:
            key, value = (r["metric"].get("job"), r["metric"].get("instance")), float(r["value"][1])
            if math.isfinite(value):  # NaN or Inf: not a target's answer
                when = last.get(key)
                targets.append({"job": key[0] or "", "instance": key[1] or "", "up": int(value == 1),
                                "last_up": when if when is not None and math.isfinite(when) else None})
    except (OSError, ValueError, KeyError, TypeError, IndexError, ArithmeticError) as e:
        return {"error": "VictoriaMetrics did not answer (%s)" % type(e).__name__}
    return {"targets": sorted(targets, key=lambda t: (t["job"], t["instance"]))}


HEALTH_PATHS = {"PREPUB": "/api/v1/health", "OIDC_ISSUER": "/.well-known/openid-configuration"}
LOCAL_NAMES = {"localhost", "127.0.0.1", "::1", "host.docker.internal"}
MAX_PROBES = 50
SAID = {"gaierror": "name not found", "ConnectionRefusedError": "refused", "TimeoutError": "no answer in 3 s",
        "ConnectionResetError": "reset", "SSLError": "TLS failed", "SSLCertVerificationError": "TLS certificate refused"}


def _tcp(host, port, timeout=3):
    with socket.create_connection((host, int(port)), timeout=timeout):
        return "connects"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # a 3xx is the answer: the probe never goes elsewhere


def _http(url, timeout=3, verify=True):
    ctx = None if verify else ssl._create_unverified_context()  # the backend's own cert, on localhost
    opener = urllib.request.build_opener(_NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    try:
        with opener.open(url, timeout=timeout) as r:
            return "HTTP %d" % r.status
    except urllib.error.HTTPError as e:
        raise OSError("HTTP %d" % e.code)
    except urllib.error.URLError as e:  # what is underneath: refused, a timeout, DNS
        raise e.reason if isinstance(e.reason, OSError) else OSError(type(e.reason).__name__)


def probes(hosts):
    """[(target, what, call)] for a hosts answer: the backend's /healthz, a health URL for
    the services that have one, a TCP connect for every other host and port."""
    out, seen = [], set()
    for name, s in (hosts.get("services") or {}).items():
        for p in s.get("ports") or []:
            if name == "bits-console-backend" and str(p.get("target")) == "8443" and p.get("published"):
                url = "https://127.0.0.1:%s/healthz" % p["published"]
                out.append(("127.0.0.1:%s" % p["published"], "GET /healthz", lambda u=url: _http(u, verify=False)))
    here = set(LOCAL_NAMES) | {str(hosts.get("host", "")).lower()} | set(hosts.get("services") or {})
    ends = [(l["host"], l["port"], l.get("scheme", "https"), l.get("key", "")) for l in hosts.get("links") or []]
    ends += [(t["host"], t["port"], "http", str(t.get("job", "")).upper().replace("-", "_"))
             for t in hosts.get("scrape") or []]  # a monitoring job named like the key: prepub
    for host, port, scheme, key in ends:
        if host in here or str(host).lower().endswith(".localhost") or (host, port) in seen:
            continue
        seen.add((host, port))
        path = next((p for k, p in HEALTH_PATHS.items() if k in key), None)
        target = "%s:%s" % (host, port)
        if path and scheme in ("http", "https"):
            url = "%s://%s%s" % (scheme, target, path)
            out.append((target, "GET " + path, lambda u=url: _http(u)))
        else:
            out.append((target, "TCP connect", lambda h=host, p=port: _tcp(h, p)))
    return out[:MAX_PROBES]


def check(hosts, workers=16, deadline=8):
    """[{target, probe, ok, said, ms}], all probes at once and within *deadline* seconds
    (a slow name lookup included); *said* names the outcome only."""
    def run(item):
        target, what, call = item
        start = time.monotonic()
        try:
            said, ok = call(), True
        except socket.timeout:
            said, ok = "no answer in 3 s", False
        except OSError as e:
            said = str(e) if str(e).startswith("HTTP ") else SAID.get(type(e).__name__, type(e).__name__)
            ok = False
        except Exception as e:  # a bad port or name: that probe fails, not the check
            said, ok = type(e).__name__, False
        return {"target": target, "probe": what, "ok": ok, "said": said,
                "ms": int((time.monotonic() - start) * 1000)}
    items = probes(hosts)
    pool = concurrent.futures.ThreadPoolExecutor(workers)
    futures = [pool.submit(run, item) for item in items]
    concurrent.futures.wait(futures, timeout=deadline)
    pool.shutdown(wait=False, cancel_futures=True)
    return [f.result() if f.done() and not f.cancelled() else
            {"target": t, "probe": w, "ok": False, "said": "no answer in %d s" % deadline, "ms": None}
            for f, (t, w, _) in zip(futures, items)]


def collect(compose, states, scrape_path=os.path.join(DIR, "monitoring", "scrape.yml"), host=None):
    """The whole answer; *compose(args)* is unlocking._compose, *states* {service: state}."""
    code, out, _ = compose(["config", "--profiles"])
    if code:
        raise ValueError("docker compose config --profiles failed (exit %d)" % code)
    profiles = [p for p in out.split() if p]
    args = sum((["--profile", p] for p in profiles), []) + ["config", "--format", "json"]
    code, out, err = compose(args)
    if code:
        raise ValueError("docker compose config failed (exit %d)" % code)
    config = json.loads(out)
    services, networks = services_view(config, states)
    try:
        with open(scrape_path) as f:
            scrape = scrape_view(f.read())
    except (OSError, yaml.YAMLError, AttributeError):
        scrape = []
    return {"host": host or socket.gethostname(), "services": services, "networks": networks,
            "links": links_view(config), "scrape": scrape}


if __name__ == "__main__":
    import unlocking
    print(json.dumps(dict(collect(unlocking._compose, {}), up=scrape_up()), indent=1))
