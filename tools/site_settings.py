#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every setting of this site in one list (ADR bits-services 0001, C), for bits-admin's
Settings page: each variable docker-compose.yml reads, its value in .env or its default,
what .env.example says of it and which services use it. Secrets only as set or not.

    tools/site_settings.py       # the JSON the host helper hands bits-admin
"""

import json
import os
import re
import sys

import yaml

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import site_profile  # noqa: E402

DIR = site_profile.DIR
VAR = re.compile(r"\$\{([A-Z_][A-Z0-9_]*)(?:(:?[-?+])([^}]*))?\}")
# Values that look like they carry a credential: withheld whole, never redacted in part
SENSITIVE = [re.compile(p) for p in (
    r"://[^\s,]*@",                                      # scheme://user:pass@ (any password)
    r"^[^\s/@:]+:[^\s@]+@",                              # user:pass@host
    r"(?i)[?&;](private_token|access_token|token|key|secret|password|passwd|sig|signature)=",
    r"\b(glpat-|ghp_|gho_|ghs_|github_pat_|xox[abpr]-)",   # GitLab, GitHub, Slack tokens
)]
SECTION = re.compile(r"^#\s*[─-]{3,}\s*(.*?)\s*[─-]*\s*$")
KEY_LINE = re.compile(r"^#?\s*([A-Z_][A-Z0-9_]*)=(.*)$")


def sensitive(value):
    return isinstance(value, str) and any(p.search(value) for p in SENSITIVE)


class _Loader(yaml.SafeLoader):
    """Compose's own tags (!reset, !override) read as plain values."""


_Loader.add_multi_constructor("!", lambda loader, suffix, node: (
    loader.construct_scalar(node) if isinstance(node, yaml.ScalarNode) else
    loader.construct_sequence(node) if isinstance(node, yaml.SequenceNode) else loader.construct_mapping(node)))


def compose_vars(text):
    """{name: {default, empty_default, services}} of the ${...} in a raw docker-compose.yml;
    empty_default: an empty value in .env gets the default too (${X:-d})."""
    out = {}

    def walk(node, service):
        if isinstance(node, dict):
            for value in node.values():
                walk(value, service)
        elif isinstance(node, list):
            for value in node:
                walk(value, service)
        elif isinstance(node, str):
            for name, op, default in VAR.findall(node):
                entry = out.setdefault(name, {"default": None, "empty_default": False, "services": set()})
                if op in ("-", ":-") and entry["default"] is None:
                    entry["default"], entry["empty_default"] = default, op == ":-"
                if service:
                    entry["services"].add(service)
    data = yaml.load(text, Loader=_Loader) or {}
    if not isinstance(data, dict):
        raise ValueError("docker-compose.yml is not a mapping")
    services = data.get("services") if isinstance(data.get("services"), dict) else {}
    for name, service in services.items():
        walk(service, name)
    walk({k: v for k, v in data.items() if k != "services"}, None)
    return {k: dict(v, services=sorted(v["services"])) for k, v in out.items()}


def example_docs(text):
    """{name: {section, doc}} from .env.example: the comment right above a key, shared by
    the keys that follow it directly, plus a "(...)" after the key."""
    out, section, block, shared = {}, "", [], ""
    for line in text.splitlines():
        line = line.rstrip()
        if not line.strip():
            block, shared = [], ""
            continue
        m = SECTION.match(line)
        if m:
            section, block, shared = m.group(1), [], ""
            continue
        m = KEY_LINE.match(line)
        if m:
            if block:
                shared, block = " ".join(block), []
            tail = re.search(r"\((.*)\)\s*$", m.group(2))
            doc = " ".join(x for x in (shared, tail.group(1) if tail else "") if x)
            out.setdefault(m.group(1), {"section": section, "doc": doc})
            continue
        if line.startswith("#"):
            if not block:
                shared = ""  # a new comment: the one before belonged to the keys above
            block.append(line.lstrip("#").strip())
    return out


def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return ""


def collect(env_path=site_profile.ENV_FILE, compose_path=os.path.join(DIR, "docker-compose.yml"),
            example_path=os.path.join(DIR, ".env.example"),
            profile_path=os.path.join(DIR, "site-profile.yaml")):
    env = site_profile.parse_env(_read(env_path))
    withheld = sorted(k for k, v in env.items() if sensitive(v) and not site_profile.is_secret(k, v))
    clean = {k: v for k, v in env.items() if k not in withheld}  # what may leave the host
    profile, _ = site_profile.import_env(clean)
    derived = site_profile.derive(profile["facts"])
    used, docs = compose_vars(_read(compose_path)), example_docs(_read(example_path))
    settings = []
    for key in sorted(set(used) | set(env) | set(docs) | set(derived)):
        value, compose = env.get(key), used.get(key) or {}
        secret = site_profile.is_secret(key, value or "")
        if value == "" and compose.get("empty_default"):
            value = None  # compose uses the default then
        origin = ("withheld" if key in withheld else
                  "derived" if key in derived and value == derived[key] else
                  "unset" if key in derived and value is None else
                  "overridden" if key in derived else
                  "set" if value is not None else "default" if compose.get("default") else "unset")
        settings.append({"key": key, "secret": secret, "origin": origin,
                         "value": None if secret or key in withheld or value is None else value,
                         "set": bool(env.get(key)), "default": None if secret else compose.get("default"),
                         "services": compose.get("services", []),
                         "section": (docs.get(key) or {}).get("section", ""),
                         "doc": (docs.get(key) or {}).get("doc", ""), "derived": derived.get(key)})
    answer = {"facts": profile["facts"], "settings": settings, "profile": profile, "withheld": withheld}
    if os.path.exists(profile_path):
        try:
            with open(profile_path) as f:
                diffs, notes = site_profile.compare(yaml.safe_load(f), clean)
            answer["profile_file"] = {"diffs": [d for d in diffs if not sensitive(d)], "notes": notes}
        except Exception as e:  # an empty or odd file: say which, nothing of it
            answer["profile_file"] = {"error": "site-profile.yaml: %s" % type(e).__name__}
    return answer


if __name__ == "__main__":
    print(json.dumps(collect(), indent=1))
