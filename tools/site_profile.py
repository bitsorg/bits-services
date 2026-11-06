#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""site_profile.py — a site's facts in one file, and the .env they imply.

    tools/site_profile.py import [.env] > site-profile.yaml    # from an existing .env
    tools/site_profile.py derive site-profile.yaml > .env.new  # the .env it implies
    tools/site_profile.py diff site-profile.yaml [.env]        # where the two differ
    tools/site_profile.py setup-env .env fact=v KEY=v KEY?=v  # what setup.sh writes

The profile holds the facts an admin enters (facts:), the derived keys a site sets
otherwise on purpose (overrides:, null = unset) and the other keys as they are
(env:). Secret-named keys never go into it, nor into a derived .env: they belong to
service-secrets.py. Values are read literally: ${...} is not expanded.
"""

import argparse
import errno
import os
import stat
import re
import sys
import tempfile
import time
from urllib.parse import urlsplit

import yaml

DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.path.join(DIR, ".env")
# setup.sh's order; keys it does not write follow, sorted.
ORDER = """SECURITY_PROXY_CONFIG_DIR BITS_SRC TLS_CERT_DIR BITS_SIGN_PROXY_URL
BITS_SIGN_PROXY_TOKEN GITLAB_API_URL BITS_FRONTEND_ORIGIN BITS_ADMINS_POLICY
BITS_ADMIN_RESOLVE_TOKEN BITS_WEBAUTHN_RP_ID BITS_WEBAUTHN_ORIGIN BITS_WEBAUTHN_ORIGINS
BITS_WEBAUTHN_CREDENTIALS BITS_WEBAUTHN_REQUIRE_UV BITS_ENROLLMENT_AUTHORITY
BITS_WEBAUTHN_REQUIRED BITS_OIDC_ISSUER BITS_OIDC_CI_AUDIENCE BITS_OIDC_JWKS_URL
BITS_CI_SIGNERS MONITORING_DATA_DIR VM_RETENTION RUNNER_SD_TOKEN RUNNER_SD_PROJECT_ID
RUNNER_SD_DESC_REGEX""".split()
SECRET_NAME = re.compile(r"(TOKEN|SECRET|PASSWORD|PASSWD|_PASS|_KEY|_KEY_ID)$")
SECRET_PATH = "/run/secrets/"  # a secret-named key may name a file there
URL_FACTS = ("gitlab_url", "frontend_origin", "backend_url")
FACTS = URL_FACTS + ("console_project", "admins_group")


def rp_id(origin):
    """setup.sh's default: the last two labels of the frontend host."""
    return ".".join((urlsplit(origin).hostname or "").split(".")[-2:])


def _text(key, value):
    """A profile value as .env text: strings and integers only (YAML true, 1.10, ...)."""
    if isinstance(value, bool) or not isinstance(value, (str, int)):
        raise ValueError("%s: a %s, not a string or an integer; quote it" % (key, type(value).__name__))
    return str(value)


def derive(facts):
    """The .env keys that follow from the facts set."""
    g, fe, be = (_text(k, facts[k]).rstrip("/") if facts.get(k) else "" for k in URL_FACTS)
    d = {}
    if g:
        d.update(GITLAB_API_URL=g + "/api/v4", BITS_OIDC_ISSUER=g,
                 BITS_OIDC_JWKS_URL=g + "/oauth/discovery/keys")
    if fe:
        d.update(BITS_FRONTEND_ORIGIN=fe, BITS_WEBAUTHN_ORIGIN=fe,
                 BITS_LOGIN_RETURN_ALLOW=fe, BITS_WEBAUTHN_RP_ID=rp_id(fe))
    if be:
        d.update(BITS_OIDC_CI_AUDIENCE=be, BITS_OIDC_LOGIN_REDIRECT=be + "/auth/callback")
    if fe and be:
        d["BITS_WEBAUTHN_ORIGINS"] = fe + "," + be
    if facts.get("console_project"):
        d["BITS_FORGE_PROJECT"] = _text("console_project", facts["console_project"])
    if facts.get("admins_group"):
        d["BITS_ADMINS_GROUP"] = _text("admins_group", facts["admins_group"])
    return d


def is_secret(key, value):
    """A secret-named key, unless it names a file (BITS_ORCH_AUDIT_TOKEN=/run/secrets/...)."""
    return bool(SECRET_NAME.search(key)) and not value.startswith(SECRET_PATH)


def parse_env(text):
    env = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = re.sub(r"^export\s+", "", key.strip())
        value = value.strip()
        end = value.find(value[:1], 1) if value[:1] in ("'", '"') else -1
        if end > 0:
            if value[end + 1:].strip() and not re.match(r"\s+#", value[end + 1:]):
                raise ValueError("%s: text after the closing quote" % key)
            value = value[1:end]
        else:
            value = re.split(r"\s#", value, 1)[0].strip()
        env[key] = value
    return env


def _strip(value, suffix):
    return value[:-len(suffix)] if value.endswith(suffix) else ""


def facts_from(env):
    """The facts an existing .env was made from."""
    found = {
        "gitlab_url": _strip(env.get("GITLAB_API_URL", "").rstrip("/"), "/api/v4")
                      or env.get("BITS_OIDC_ISSUER", ""),
        "frontend_origin": env.get("BITS_FRONTEND_ORIGIN") or env.get("BITS_WEBAUTHN_ORIGIN", ""),
        "backend_url": _strip(env.get("BITS_OIDC_LOGIN_REDIRECT", ""), "/auth/callback")
                       or env.get("BITS_OIDC_CI_AUDIENCE", ""),
        "console_project": env.get("BITS_FORGE_PROJECT", ""),
        "admins_group": env.get("BITS_ADMINS_GROUP", ""),
    }
    return {k: v.rstrip("/") if k in URL_FACTS else v for k, v in found.items() if v}


def import_env(env):
    """(profile, names of the secrets left out) for an existing .env."""
    facts = facts_from(env)
    derived = derive(facts)
    profile = {"facts": facts, "overrides": {}, "env": {}}
    secrets = []
    for key, value in env.items():
        if key in derived:
            if value != derived[key]:
                profile["overrides"][key] = value
        elif is_secret(key, value):
            if value:
                secrets.append(key)
        else:
            profile["env"][key] = value
    for key in derived:
        if key not in env:
            profile["overrides"][key] = None
    return profile, secrets


def derive_env(profile):
    """The .env a profile implies, in setup.sh's order, without secret-named keys."""
    if not isinstance(profile, dict):
        raise ValueError("the profile is not a mapping")
    facts, overrides, extra = (profile.get(k) or {} for k in ("facts", "overrides", "env"))
    if not all(isinstance(x, dict) for x in (facts, overrides, extra)):
        raise ValueError("facts:, overrides: and env: must be mappings")
    env = derive(facts)
    for key, value in overrides.items():
        if value is None:
            env.pop(key, None)
        else:
            env[key] = _text(key, value)
    for key, value in extra.items():
        if key in env or key in overrides:
            raise ValueError("%s: derived or overridden, so not in env:" % key)
        env[key] = _text(key, value)
    env = {k: v for k, v in env.items() if not is_secret(k, v)}
    rank = {k: i for i, k in enumerate(ORDER)}
    return dict(sorted(env.items(), key=lambda kv: (rank.get(kv[0], len(ORDER)), kv[0])))


def render_env(env, header="# generated by tools/site_profile.py from the site profile"):
    lines = [header]
    for key, value in env.items():
        if any(c in value for c in "'\r\n"):
            raise ValueError("%s: a quote or a line break cannot be written to .env" % key)
        lines.append("%s='%s'" % (key, value))
    return "\n".join(lines) + "\n"


def check(profile):
    """Rules the facts must keep: the passkey rp_id fits both origins."""
    env = derive_env(profile)
    origins = [o for o in [env.get("BITS_WEBAUTHN_ORIGIN", "")]
               + env.get("BITS_WEBAUTHN_ORIGINS", "").split(",") if o]
    rp = env.get("BITS_WEBAUTHN_RP_ID", "").lower()
    if origins and not rp:
        return ["rp_id is unset"]
    problems = []
    for origin in origins:
        host = urlsplit(origin).hostname or ""
        if not host:
            problems.append("origin %s has no host" % origin)
        elif host != rp and not host.endswith("." + rp):
            problems.append("rp_id %s is not a parent of %s" % (rp, host))
    return sorted(set(problems))


def compare(profile, env):
    """(differences, notes) between the .env a profile implies and an actual one."""
    want, diffs, notes = derive_env(profile), [], []
    for key in sorted(set(want) | set(env)):
        if key in env and is_secret(key, env[key]):  # never printed
            if env[key]:
                notes.append("secret in .env: %s (move it to service secrets)" % key)
        elif key not in env:
            diffs.append("only in the profile: %s=%s" % (key, want[key]))
        elif key not in want:
            diffs.append("only in .env: %s=%s" % (key, env[key]))
        elif want[key] != env[key]:
            diffs.append("differs: %s: .env %s, profile %s" % (key, env[key], want[key]))
    derived = derive(profile.get("facts") or {})
    for key, value in sorted((profile.get("overrides") or {}).items()):
        notes.append("override: %s (derived: %s)" % (key, derived.get(key)))
    return diffs + ["error: " + p for p in check(profile)], notes


def raw_lines(text):
    """The last line of each key as written, for the values carried over verbatim."""
    lines = {}
    for line in text.splitlines():
        key = re.sub(r"^export\s+", "", line.strip().split("=", 1)[0].strip())
        if "=" in line and not line.strip().startswith("#"):
            lines[key] = line.strip()
    return lines


def setup_env(old, facts, sets, defaults):
    """setup.sh's .env: the old one with its answers, defaults where a key is unset or
    empty (bash ${K:-v}), the derived keys it lacked; (plain keys, secret names).
    An old derived value follows the new facts unless it differed on purpose."""
    env = dict(old)
    env.update({k: v for k, v in defaults.items() if not env.get(k)})
    env.update(sets)
    facts = dict(facts_from(env), **{k: v for k, v in facts.items() if v})
    for key in URL_FACTS:
        if key in facts and not urlsplit(str(facts[key])).hostname:
            raise ValueError("%s %s has no host" % (key, facts[key]))
    derived, was = derive(facts), derive(facts_from(old))
    overrides = {}
    for key in derived:
        value = sets.get(key, env.get(key))
        if value is not None and value != derived[key] and (key in sets or value != was.get(key)):
            overrides[key] = value
    profile = {"facts": facts, "overrides": overrides,
               "env": {k: v for k, v in env.items() if k not in derived and not is_secret(k, v)}}
    problems = check(profile)
    if problems:
        raise ValueError("; ".join(problems))
    return derive_env(profile), [k for k, v in env.items() if v and is_secret(k, v)]


def unquoted_expansions(text):
    """Keys whose value compose would expand ($ or \\ outside single quotes), but for
    secret-named ones, which are carried over as written."""
    found = []
    for key, line in raw_lines(text).items():
        value = line.split("=", 1)[1].strip()
        if is_secret(key, value) or value.startswith("'"):
            continue
        if "$" in value or "\\" in value:
            found.append(key)
    return found


def read_regular(path, limit=1 << 20):
    """(text, stat) of a regular file, (None, None) if there is none; never through a
    symbolic link, nor from a FIFO or a device (the helper reads as root)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None, None
    except OSError as e:
        if e.errno == errno.ELOOP:
            raise ValueError("%s is a symbolic link; replace it with the file" % os.path.basename(path))
        raise
    with os.fdopen(fd, encoding="utf-8") as f:
        st = os.fstat(fd)
        try:
            text = f.read(limit + 1) if stat.S_ISREG(st.st_mode) else None
        except UnicodeDecodeError:  # its message would quote a byte
            raise ValueError("%s is not UTF-8 text" % os.path.basename(path)) from None
        if text is None or len(text) > limit:
            raise ValueError("%s is not a file of at most %d characters" % (os.path.basename(path), limit))
        return text, st


def write_env(path, text):
    """Replaces path in one step, mode 600, owner kept (a new file: its directory's); a
    changed old file is kept as <path>.bak-<time>. (written, backup); unchanged if only
    its date differs."""
    old, st = read_regular(path)
    if old == text or old is not None and old.startswith("# generated by") \
            and old.split("\n", 1)[1:] == text.split("\n", 1)[1:]:
        return False, None
    directory = os.path.dirname(os.path.abspath(path))
    fd, tmp = tempfile.mkstemp(prefix=os.path.basename(path) + ".new-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            os.fchmod(f.fileno(), 0o600)
            st = st or os.stat(directory)
            owner = (st.st_uid, st.st_gid) if (st.st_uid, st.st_gid) != (os.getuid(), os.getgid()) else None
            if owner:
                os.fchown(f.fileno(), *owner)
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        backup = None
        if old is not None:
            stamp = "%s.bak-%s" % (path, time.strftime("%Y%m%dT%H%M%SZ", time.gmtime()))
            backup, n = stamp, 1
            while os.path.lexists(backup):
                backup, n = "%s-%d" % (stamp, n), n + 1
            with os.fdopen(os.open(backup, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "w", encoding="utf-8") as f:
                if owner:  # the owner may put it back without sudo
                    os.fchown(f.fileno(), *owner)
                f.write(old)
        os.replace(tmp, path)
        return True, backup
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


def _assignments(args):
    """fact=value (a profile fact), KEY=value (set), KEY?=value (a default)."""
    facts, sets, defaults = {}, {}, {}
    for arg in args:
        key, sep, value = arg.partition("=")
        name = key.rstrip("?")
        if not sep or not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", name):
            raise ValueError("%s: not fact=value, KEY=value or KEY?=value" % arg)
        if name in FACTS:
            facts[name] = value
        else:
            (defaults if key.endswith("?") else sets)[name] = value
    return facts, sets, defaults


def _read(path):
    with open(path) as f:
        return f.read()


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="command", required=True)
    sub.add_parser("import").add_argument("env", nargs="?", default=ENV_FILE)
    sub.add_parser("derive").add_argument("profile")
    p = sub.add_parser("diff")
    p.add_argument("profile")
    p.add_argument("env", nargs="?", default=ENV_FILE)
    p = sub.add_parser("setup-env")
    p.add_argument("env")
    p.add_argument("assignments", nargs="*")
    a = ap.parse_args()
    if a.command == "setup-env":
        try:
            facts, sets, defaults = _assignments(a.assignments)
            text = _read(a.env) if os.path.exists(a.env) else ""
            expanding = unquoted_expansions(text)
            if expanding:
                raise ValueError("compose would expand $ or \\ in %s: put the value in single quotes"
                                 % ", ".join(expanding))
            plain, secrets = setup_env(parse_env(text), facts, sets, defaults)
            out = render_env(plain, "# generated by scripts/setup.sh %s, re-run: make init"
                             % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
            if secrets:  # as written, never re-quoted
                raw = raw_lines(text)
                out += "\n".join(["# secrets, kept as they were: they belong in service secrets"]
                                  + [raw[k] for k in secrets]) + "\n"
            written, backup = write_env(a.env, out)
        except (OSError, ValueError) as e:
            sys.exit("error: %s" % e)
        print(("wrote %s" % a.env if written else "%s unchanged" % a.env)
              + (" (the old one: %s)" % backup if backup else ""))
        return 0
    try:
        if a.command == "import":
            profile, secrets = import_env(parse_env(_read(a.env)))
            sys.stdout.write("# site profile, imported from %s\n" % a.env)
            yaml.safe_dump(profile, sys.stdout, sort_keys=False, default_flow_style=False)
            for key in secrets:
                print("left out, a secret: %s (move it to service secrets)" % key, file=sys.stderr)
            return 0
        profile = yaml.safe_load(_read(a.profile)) or {}
        if a.command == "derive":
            problems = check(profile)
            if problems:
                sys.exit("\n".join("error: " + p for p in problems))
            sys.stdout.write(render_env(derive_env(profile)))
            return 0
        diffs, notes = compare(profile, parse_env(_read(a.env)))
    except (ValueError, yaml.YAMLError) as e:
        sys.exit("error: %s" % e)
    for line in notes + diffs:
        print(line)
    print("%d difference(s)" % len(diffs))
    return 1 if diffs else 0


if __name__ == "__main__":
    sys.exit(main())
