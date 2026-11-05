#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""site_report.py — where a site's copies of the same facts disagree (read-only).

    tools/site_report.py [--console DIR] [--slots] [--gitlab]

It reads .env (through site_profile.py), the proxies' configs and scrape.yml here,
with --console a bits-console checkout's communities and config, with --slots the
stored service-secret names (asks the passphrase), with --gitlab the console
project's CI/CD variables and schedules (asks a Maintainer token, used once). It
prints names and plain settings, never a secret's value. Exit 1 if a copy differs.
"""

import argparse
import getpass
import glob
import json
import os
import subprocess
import sys
import urllib.error
import urllib.request
from urllib.parse import quote, urlsplit

import yaml

import site_profile as sp

# The console CI/CD variables (ADR bits-services 0001, section E).
CI_NEEDED = ("PREPUB_URL", "PREPUB_API_TOKEN", "BITS_STATUS_TOKEN", "BITS_READ_TOKEN")
CI_MASKED = ("PREPUB_API_TOKEN", "BITS_STATUS_TOKEN", "BITS_READ_TOKEN", "AWS_ACCESS_KEY_ID",
             "AWS_SECRET_ACCESS_KEY")
CI_PLAIN = ("PREPUB_URL", "BITS_ORCH_URL", "METRICS_URL", "REMOTE_STORE", "BITS_REPO", "BITS_REF")
CI_OBSOLETE = ("CERTIFY_MANIFESTS_REMOTE", "BITS_FORGE_TOKEN", "NIGHTLY_FAN_OUT")
BACKEND_KEYS = ("signing_backend_url", "catalog_backend_url", "ops_backend_url", "session_backend_url")
KNOWN_SLOTS = ("client-cert",)  # service-secrets.py's own
# What the backend no longer reads once BITS_CRED_PROXY_AGENT_SOCKET is set (config.py).
PROXIED = ("BITS_FORGE_OPS_TOKEN", "BITS_FORGE_READ_TOKEN", "BITS_ADMIN_RESOLVE_TOKEN",
           "BITS_ORCH_S3_ACCESS_KEY_ID", "BITS_ORCH_S3_SECRET_ACCESS_KEY")
PORTS = {"http": 80, "https": 443}


class Report:
    def __init__(self):
        self.lines, self.problems = [], 0

    def section(self, title):
        self.lines.append("== " + title)

    def ok(self, text):
        self.lines.append("ok        " + text)

    def note(self, text):
        self.lines.append("note      " + text)

    def bad(self, kind, text):
        self.problems += 1
        self.lines.append("%-9s %s" % (kind, text))


def _place(url):
    """(host, port) of a URL or a host:port, lowercased, default ports filled in."""
    u = urlsplit(url.strip() if "//" in url else "//" + url.strip())
    try:
        port = u.port or PORTS.get(u.scheme)
    except ValueError:
        port = None
    return (u.hostname or "", port)


def _shown(url):
    """A URL without any user:password@ in it, for printing."""
    u = urlsplit(url)
    return u._replace(netloc=u.netloc.rsplit("@", 1)[-1]).geturl() if "@" in u.netloc else url


def _same_url(a, b):
    return a.strip().rstrip("/") == b.strip().rstrip("/")


def _load(path, kind=dict):
    with open(path) as f:
        data = json.load(f) if path.endswith(".json") else yaml.safe_load(f)
    data = kind() if data is None else data
    if not isinstance(data, kind):
        raise ValueError("%s is not a %s" % (path, "mapping" if kind is dict else "list"))
    return data


def _ingests(node):
    """The ingest slot names anywhere in a proxy route."""
    if isinstance(node, dict):
        found = {node["ingest"]} if isinstance(node.get("ingest"), str) else set()
        return found.union(*map(_ingests, node.values()))
    if isinstance(node, list):
        return set().union(*map(_ingests, node))
    return set()


def check_env(r, env):
    profile, secrets = sp.import_env(env)
    proxied = env.get("BITS_CRED_PROXY_AGENT_SOCKET") and set(PROXIED)
    for key in secrets:
        if proxied and key in proxied:
            r.bad("leftover", "%s is in .env, replaced by the credentials proxy: remove it once "
                              "make credentials-check passes" % key)
        else:
            r.bad("secret", "%s is in .env, where the services can read it; no proxy slot "
                            "replaces it yet" % key)
    diffs, notes = sp.compare(profile, env)
    for line in diffs:  # only the check() errors can remain after an import
        r.bad("differs", line)
    for line in notes:
        if line.startswith("override:"):
            r.note(line)
    if not secrets and not diffs:
        r.ok("no secret in .env, the derived keys agree")
    return profile["facts"]


def proxy_slots(r, services, env, facts, wanted):
    """Collects the ingest slots the proxies' configs ask for; checks their upstreams."""
    for var, default in (("CREDENTIALS_PROXY_CONFIG_DIR", "./config/credentials-proxy"),
                         ("STORE_WRITER_CONFIG_DIR", "./config/store-writer")):
        path = os.path.join(services, env.get(var) or default, "config.json")
        if not os.path.exists(path):
            r.note("%s: not there" % path)
            continue
        for route in _load(path).get("routes") or []:
            if not isinstance(route, dict):
                r.bad("error", "%s: a route that is not a mapping" % path)
                continue
            up, name = str(route.get("upstream", "")), route.get("name")
            wanted |= _ingests(route)
            other = env.get("BITS_ORCH_S3_ENDPOINT", "") if route.get("s3") else facts.get("gitlab_url", "")
            if other and _place(up) != _place(other):
                r.bad("differs", "%s route %s: upstream %s, the site %s" % (path, name, _shown(up), _shown(other)))
    r.ok("slots asked for: %s" % (", ".join(sorted(wanted)) or "none"))


def check_slots(r, services, wanted, run=subprocess.run):
    tool = os.path.join(services, "tools", "service-secrets.py")
    out = run([sys.executable, tool, "list"], stdout=subprocess.PIPE, text=True)
    if out.returncode:
        r.bad("error", "service-secrets.py list failed")
        return
    stored = {line.strip() for line in out.stdout.splitlines() if line.strip()}
    for slot in sorted(wanted - stored):
        r.bad("missing", "slot %s: a proxy asks for it, none is stored" % slot)
    for slot in sorted(stored - wanted - set(KNOWN_SLOTS)):
        r.note("slot %s: stored, no proxy asks for it" % slot)
    if wanted <= stored:
        r.ok("every slot a proxy asks for is stored")


def prepub_targets(services):
    for job in _load(os.path.join(services, "monitoring", "scrape.yml")).get("scrape_configs") or []:
        if isinstance(job, dict) and job.get("job_name") == "prepub":
            return {_place(str(t)) for c in job.get("static_configs") or [] if isinstance(c, dict)
                    for t in c.get("targets") or []}
    return set()


def _same_kind(a, b):
    return str(a).isdigit() == str(b).isdigit()


def check_console(r, console, facts, env, services, prepub):
    """Checks the console's copies; collects its prepub services into prepub."""
    files = sorted(glob.glob(os.path.join(console, "communities", "*", "ui-config.yaml")))
    files.append(os.path.join(console, "config", "console.yaml"))
    want = {"gitlab_url": facts.get("gitlab_url"), "project_id": facts.get("console_project")}
    want.update({k: facts.get("backend_url") for k in BACKEND_KEYS})
    listed = {}
    for path in files:
        name = os.path.relpath(path, console)
        try:
            cfg = _load(path)
        except (OSError, ValueError, yaml.YAMLError) as e:
            r.bad("error", "%s: %s" % (name, e))
            continue
        for key, value in want.items():
            if key not in cfg or not value:
                continue
            if key == "project_id" and not _same_kind(cfg[key], value):
                r.note("%s project_id %s and BITS_FORGE_PROJECT %s: an id and a path, not compared"
                       % (name, cfg[key], value))
            elif not _same_url(str(cfg[key]), str(value)):
                r.bad("differs", "%s %s: %s, the site %s" % (name, key, _shown(str(cfg[key])), _shown(str(value))))
        entries = cfg.get("prepub_services") or []
        if not isinstance(entries, list):
            r.bad("error", "%s prepub_services is not a list" % name)
            continue
        for entry in entries:
            listed[str(entry).split("|")[-1].strip()] = name
    prepub |= set(listed)
    orch = {u.strip() for u in env.get("BITS_ORCH_PREPUB_URLS", "").split(",") if u.strip()}
    for url in sorted(orch):
        if listed and not any(_same_url(url, u) for u in listed):
            r.bad("differs", "prepub %s: in BITS_ORCH_PREPUB_URLS, not in the console's prepub_services"
                  % _shown(url))
    scraped = prepub_targets(services)
    for url, name in sorted(listed.items()):
        if orch and not any(_same_url(url, u) for u in orch):
            r.bad("differs", "prepub %s: in %s, not in BITS_ORCH_PREPUB_URLS" % (_shown(url), name))
        if _place(url) not in scraped:
            r.bad("differs", "prepub %s: in %s, not scraped (scrape.yml)" % (_shown(url), name))
    for host, port in sorted(scraped - {_place(u) for u in listed}, key=str):
        r.bad("differs", "prepub %s:%s: scraped, not in the console's prepub_services" % (host, port))
    r.ok("%d console file(s) read" % len(files))


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None  # the token is never sent on to another place


def gitlab_fetch(api, token):
    """A read-only GET of every page of a GitLab list; no redirects followed."""
    opener = urllib.request.build_opener(_NoRedirect)

    def fetch(path):
        items, page = [], "1"
        while page:
            req = urllib.request.Request("%s%s?per_page=100&page=%s" % (api, path, page),
                                         headers={"PRIVATE-TOKEN": token})
            with opener.open(req, timeout=30) as resp:
                data = json.load(resp)
                page = resp.headers.get("X-Next-Page", "")
            if not isinstance(data, list):
                raise ValueError("%s: not a list" % path)
            items += data
        return items
    return fetch


def _label(v):
    scope = v.get("environment_scope") or "*"
    return v["key"] if scope == "*" else "%s[%s]" % (v["key"], scope)


def check_gitlab(r, facts, prepub, fetch):
    project = "/projects/%s" % quote(str(facts["console_project"]), safe="")
    variables = [v for v in fetch(project + "/variables") if isinstance(v, dict) and "key" in v]
    keys = {v["key"] for v in variables}
    for key in CI_NEEDED:
        if key not in keys:
            r.bad("missing", "variable %s: not on the project (unless a group variable or the "
                             "runners' config.toml gives it)" % key)
    if "BITS_ORCH_URL" not in keys:
        r.note("BITS_ORCH_URL not on the project: unless a group variable or the runners' config.toml "
               "gives it, jobs send no finished hint (the worker finds them on its next pass)")
    for v in sorted(variables, key=_label):
        key = v["key"]
        if key in CI_OBSOLETE:
            r.bad("obsolete", "variable %s: no longer read once the console CI retires it" % _label(v))
            continue
        secret = key in CI_MASKED or sp.is_secret(key, "")
        if secret:
            if not v.get("protected"):
                r.bad("unsafe", "variable %s is a secret, not protected: any branch's pipeline can read it"
                      % _label(v))
            if not v.get("masked"):
                r.bad("unsafe", "variable %s is a secret but not masked" % _label(v))
        if key not in CI_PLAIN or v.get("masked") or secret:
            continue  # only plain settings are ever shown
        value = str(v.get("value") or "")
        r.note("%s=%s" % (_label(v), _shown(value)))
        if key == "BITS_ORCH_URL" and facts.get("backend_url") and not _same_url(value, facts["backend_url"]):
            r.bad("differs", "%s %s, the backend %s" % (_label(v), _shown(value), facts["backend_url"]))
        if key == "PREPUB_URL" and prepub and not any(_same_url(value, u) for u in prepub):
            r.bad("differs", "%s %s is not one of the console's prepub services" % (_label(v), _shown(value)))
    for s in fetch(project + "/pipeline_schedules"):
        if isinstance(s, dict) and s.get("active"):
            r.bad("obsolete", "schedule %s (%s): the orchestrator runs the nightlies"
                  % (s.get("id"), s.get("description", "")))


def gitlab_section(r, facts, prepub, token):
    """The GitLab checks, with errors told by kind only: the token is never shown."""
    gitlab = facts.get("gitlab_url", "")
    if not facts.get("console_project") or not gitlab.startswith("https://"):
        r.bad("error", "needs BITS_FORGE_PROJECT and an https GitLab URL in .env")
        return
    token = token.strip()
    if not token or not all(33 <= ord(c) < 127 for c in token):
        r.bad("error", "the token is empty or has characters a token cannot have")
        return
    try:
        check_gitlab(r, facts, prepub, gitlab_fetch(gitlab + "/api/v4", token))
    except urllib.error.HTTPError as e:
        r.bad("error", "GitLab answered %s (a Maintainer token with read_api is needed)" % e.code)
    except Exception as e:  # never str(e): it could carry the token
        r.bad("error", "reading GitLab failed: %s" % type(e).__name__)


def _run(r, title, step):
    r.section(title)
    try:
        return step()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, yaml.YAMLError) as e:
        r.bad("error", "%s: %s" % (type(e).__name__, e))


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--services", default=sp.DIR, help="the bits-services directory")
    ap.add_argument("--console", help="a bits-console checkout")
    ap.add_argument("--slots", action="store_true", help="the stored service-secret names")
    ap.add_argument("--gitlab", action="store_true", help="the console project's variables")
    a = ap.parse_args()
    token = ""
    if a.gitlab:
        try:
            token = os.environ.get("GITLAB_TOKEN") or getpass.getpass("GitLab token (Maintainer): ")
        except (EOFError, KeyboardInterrupt):
            sys.exit("no token given")
    r, wanted, prepub = Report(), set(), set()
    env = _run(r, ".env", lambda: sp.parse_env(sp._read(os.path.join(a.services, ".env"))))
    if env is None:
        print("\n".join(r.lines))
        return 1
    facts = _run(r, ".env facts", lambda: check_env(r, env)) or {}
    _run(r, "proxy configs", lambda: proxy_slots(r, a.services, env, facts, wanted))
    if a.slots:
        _run(r, "service secrets", lambda: check_slots(r, a.services, wanted))
    if a.console:
        _run(r, "console checkout", lambda: check_console(r, a.console, facts, env, a.services, prepub))
    if a.gitlab:
        r.section("GitLab project %s" % facts.get("console_project"))
        gitlab_section(r, facts, prepub, token)
    print("\n".join(r.lines))
    print("%d problem(s)" % r.problems)
    return 1 if r.problems else 0


if __name__ == "__main__":
    sys.exit(main())
