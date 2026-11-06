#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""What bits-admin's Hosts page shows (ADR bits-services 0001, H): this host's services
with their ports and Docker networks, the hosts and ports they connect to, and the hosts
monitoring scrapes. Only names, hosts and ports: never a value of a secret.

    tools/site_hosts.py          # the JSON the host helper hands bits-admin
"""

import json
import os
import re
import socket
import sys
from urllib.parse import urlsplit

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from site_profile import SECRET_NAME  # noqa: E402

DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
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
    print(json.dumps(collect(unlocking._compose, {}), indent=1))
