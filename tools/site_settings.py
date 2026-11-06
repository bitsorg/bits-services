#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Every setting of this site in one list (ADR bits-services 0001, C), for bits-admin's
Settings page: each variable docker-compose.yml reads, its value in .env or its default,
what .env.example says of it and which services use it. Secrets only as set or not.

    tools/site_settings.py       # the JSON the host helper hands bits-admin
"""

import hashlib
import hmac
import json
import os
import re
import sys
import time

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


COMPOSE, EXAMPLE = os.path.join(DIR, "docker-compose.yml"), os.path.join(DIR, ".env.example")


def collect(env_path=site_profile.ENV_FILE, compose_path=COMPOSE, example_path=EXAMPLE,
            profile_path=os.path.join(DIR, "site-profile.yaml")):
    text = _read(env_path)
    env = site_profile.parse_env(text)
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
    answer = {"facts": profile["facts"], "settings": settings, "profile": profile, "withheld": withheld,
              "base": _base(text)}  # what plan() calls base
    if os.path.exists(profile_path):
        try:
            with open(profile_path) as f:
                diffs, notes = site_profile.compare(yaml.safe_load(f), clean)
            answer["profile_file"] = {"diffs": [d for d in diffs if not sensitive(d)], "notes": notes}
        except Exception as e:  # an empty or odd file: say which, nothing of it
            answer["profile_file"] = {"error": "site-profile.yaml: %s" % type(e).__name__}
    return answer


NAME = re.compile(r"^[A-Z_][A-Z0-9_]{0,63}$")
NOT_HERE = re.compile(r"^(COMPOSE|DOCKER)_")  # they steer compose itself, not a service
_KEY = os.urandom(32)  # this process's: a base names an .env, yet tells nothing of its secrets


def _base(text):
    return hmac.new(_KEY, text.encode(), hashlib.sha256).hexdigest()


class Refused(ValueError):
    """A change this cannot make; its message names keys and rules, never a kept value."""


def _changes(changes):
    """(facts, sets, unsets, follows) of a plan's changes, checked; follows: derived keys
    that are to follow the facts again."""
    if not isinstance(changes, dict):
        raise Refused("changes are a mapping")
    facts, sets, unsets, follows = (changes.get(k) or empty for k, empty in (
        ("facts", {}), ("set", {}), ("unset", []), ("follow", [])))
    if not (isinstance(facts, dict) and isinstance(sets, dict) and isinstance(unsets, list)
            and isinstance(follows, list)):
        raise Refused("facts and set are mappings, unset and follow lists")
    for name, value in list(facts.items()) + list(sets.items()):
        if not isinstance(value, str) or len(value) > 4096 or not value.isprintable():
            raise Refused("%s: a text of at most 4096 characters, on one line" % name)
    if set(facts) - set(site_profile.FACTS):
        raise Refused("not facts: %s" % ", ".join(sorted(set(facts) - set(site_profile.FACTS))))
    for key in list(sets) + unsets + follows:
        if not isinstance(key, str) or not NAME.match(key):
            raise Refused("%r is not a setting's name" % (str(key)[:64],))
        if NOT_HERE.match(key):
            raise Refused("%s steers docker compose itself: change it by hand" % key)
    return facts, sets, unsets, follows


def edited(text, changes, known=None):
    """(the new .env text, [(key, old, new)]) after *changes*; secrets and withheld values
    are kept as written and cannot be changed here (they are service secrets). A new key
    must be one of *known* (what compose reads or .env.example names)."""
    facts, sets, unsets, follows = _changes(changes)
    try:
        expanding = site_profile.unquoted_expansions(text)
        old = site_profile.parse_env(text)
    except ValueError as e:  # site_profile's own words: a key and a rule
        raise Refused(".env: %s" % e)
    if expanding:
        raise Refused("compose would expand $ or \\ in %s: put the value in single quotes by hand first"
                      % ", ".join(expanding))
    kept = [k for k, v in old.items() if v and (site_profile.is_secret(k, v) or sensitive(v))]
    touched = [k for k in list(sets) + unsets + follows if k in kept or site_profile.is_secret(k, sets.get(k, ""))
               or sensitive(sets.get(k))] + [k for k, v in facts.items() if sensitive(v)]
    if touched:
        raise Refused("not here, they are secrets: %s" % ", ".join(sorted(set(touched))))
    visible = {k: v for k, v in old.items() if k not in kept}  # facts never come from a credential
    facts = dict(site_profile.facts_from(visible), **facts)  # a followed key may be what a fact came from
    derived_now, derived_then = site_profile.derive(site_profile.facts_from(visible)), site_profile.derive(facts)
    unknown = set(sets) - set(old) - set(derived_then) - set(known if known is not None else sets)
    if unknown:
        raise Refused("neither docker-compose.yml nor .env.example knows %s" % ", ".join(sorted(unknown)))
    if set(unsets) & set(derived_now):
        raise Refused("follow the facts, so cannot be unset: %s" % ", ".join(sorted(set(unsets) & set(derived_now))))
    if set(follows) - set(derived_then):
        raise Refused("follow no fact: %s" % ", ".join(sorted(set(follows) - set(derived_then))))
    base = {k: v for k, v in old.items() if k not in kept and k not in unsets and k not in follows}
    try:
        plain, _ = site_profile.setup_env(base, facts, sets, {})
        plain = {k: v for k, v in plain.items() if k not in kept}  # a kept line wins, once
        out = site_profile.render_env(plain, "# generated by bits-admin %s; change it there"
                                      % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
    except Refused:
        raise
    except ValueError as e:
        raise Refused(str(e))
    if kept:  # as written, never re-quoted
        raw = site_profile.raw_lines(text)
        out += "\n".join(["# secrets, kept as they were: they belong in service secrets"]
                         + [raw[k] for k in kept]) + "\n"
    new = site_profile.parse_env(out)
    diff = [(k, old.get(k), new.get(k)) for k in sorted(set(old) | set(new))
            if old.get(k) != new.get(k)]
    leaking = [k for k, _, v in diff if v and (site_profile.is_secret(k, v) or sensitive(v))]
    if leaking:  # a credential must not become a plain setting, nor show in the plan
        raise Refused("would write a credential into %s" % ", ".join(leaking))
    return out, diff


def _known(compose_path, example_path):
    return set(compose_vars(_read(compose_path))) | set(example_docs(_read(example_path)))


def plan(changes, env_path=site_profile.ENV_FILE, compose_path=None, example_path=None):
    """{base, diff}: what applying *changes* to .env would do; base names .env then."""
    text = _read(env_path)
    _, diff = edited(text, changes, _known(compose_path or COMPOSE, example_path or EXAMPLE))
    return {"base": _base(text),
            "diff": [{"key": k, "old": o, "new": n} for k, o, n in diff]}


def apply(changes, base, env_path=site_profile.ENV_FILE, compose_path=None, example_path=None):
    """Writes .env as plan() showed, if it is still the .env of that plan."""
    text = _read(env_path)
    if not hmac.compare_digest(_base(text), str(base)):
        raise Refused(".env changed since the plan: plan again")
    out, diff = edited(text, changes, _known(compose_path or COMPOSE, example_path or EXAMPLE))
    written, backup = site_profile.write_env(env_path, out)
    return {"written": written, "backup": os.path.basename(backup) if backup else None,
            "keys": [k for k, _, _ in diff]}


if __name__ == "__main__":
    print(json.dumps(collect(), indent=1))
