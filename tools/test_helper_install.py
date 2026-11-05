# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/helper-install.sh, with getent, groupadd, systemctl and id stood in."""

import os
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts",
                      "helper-install.sh")
SHIMS = {
    "id": 'echo "${FAKE_UID:-0}"',
    "getent": 'grep -E "^$2:|:$2:" "$FAKE_GROUPS" || exit 2',
    "groupadd": 'echo "$4:x:$3:" >> "$FAKE_GROUPS"; echo "groupadd $*" >> "$FAKE_LOG"',
    "systemctl": 'echo "systemctl $*" >> "$FAKE_LOG"; [ "$1" = is-enabled ] && echo "${FAKE_ENABLED:-disabled}";'
                 ' [ "$1" = is-active ] && exit "${FAKE_ACTIVE:-0}"; exit 0',
}


class HelperInstallTest(unittest.TestCase):
    def run_install(self, groups, uid="0", script=SCRIPT, old_unit=None, **env_extra):
        with tempfile.TemporaryDirectory() as d:
            bin_dir, units = os.path.join(d, "bin"), os.path.join(d, "units")
            os.makedirs(bin_dir)
            os.makedirs(units)
            for name, body in SHIMS.items():
                with open(os.path.join(bin_dir, name), "w") as f:
                    f.write("#!/bin/bash\n" + body + "\n")
                os.chmod(os.path.join(bin_dir, name), 0o755)
            group_file, log = os.path.join(d, "group"), os.path.join(d, "log")
            with open(group_file, "w") as f:
                f.write(groups)
            open(log, "w").close()
            unit = os.path.join(units, "bits-admin-helper.service")
            if old_unit is not None:
                with open(unit, "w") as f:
                    f.write(old_unit)
            env = dict(os.environ, PATH=bin_dir + ":" + os.environ["PATH"], FAKE_GROUPS=group_file,
                       FAKE_LOG=log, FAKE_UID=uid, UNIT_DIR=units, **env_extra)
            r = subprocess.run(["bash", script], env=env, capture_output=True, text=True)
            self.assertEqual([f for f in os.listdir(units) if f.startswith(".")], [])  # no temp left
            with open(log) as f:
                calls = f.read()
            text = ""
            if os.path.exists(unit):
                with open(unit) as f:
                    text = f.read()
            return r, calls, text

    def test_creates_a_missing_group(self):
        r, calls, unit = self.run_install("docker:x:995:\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("groupadd --system --gid 10004 bits-admin-helper", calls)
        self.assertIn("systemctl restart bits-admin-helper", calls)
        self.assertIn("ExecStart=/usr/bin/python3 %s/tools/bits-admin-helper.py serve"
                      % os.path.dirname(os.path.dirname(SCRIPT)), unit)

    def test_keeps_a_matching_group(self):
        r, calls, _ = self.run_install("bits-admin-helper:x:10004:\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("groupadd", calls)

    def test_refuses_a_group_with_another_gid(self):
        r, calls, unit = self.run_install("bits-admin-helper:x:10005:\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("exists with gid 10005, not 10004", r.stderr)
        self.assertNotIn("groupadd", calls)
        self.assertNotIn("restart", calls)
        self.assertEqual(unit, "")

    def test_refuses_a_gid_taken_by_another_group(self):
        r, calls, unit = self.run_install("something:x:10004:\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("gid 10004 belongs to group something", r.stderr)
        self.assertNotIn("groupadd", calls)
        self.assertNotIn("restart", calls)
        self.assertEqual(unit, "")

    def test_refuses_a_masked_unit(self):
        r, calls, _ = self.run_install("", FAKE_ENABLED="masked")
        self.assertEqual(r.returncode, 1)
        self.assertIn("masked", r.stderr)
        self.assertNotIn("restart", calls)

    def test_a_failed_start_is_reported(self):
        r, _, _ = self.run_install("bits-admin-helper:x:10004:\n", FAKE_ACTIVE="3")
        self.assertEqual(r.returncode, 1)

    def test_a_tree_without_template_keeps_the_old_unit(self):
        with tempfile.TemporaryDirectory() as tree:
            os.makedirs(os.path.join(tree, "scripts"))
            copy = os.path.join(tree, "scripts", "helper-install.sh")
            with open(SCRIPT) as src, open(copy, "w") as dst:
                dst.write(src.read())
            r, _, unit = self.run_install("", script=copy, old_unit="[Unit]\nold\n")
            self.assertEqual(r.returncode, 1)
            self.assertEqual(unit, "[Unit]\nold\n")

    def test_refuses_an_odd_path(self):
        with tempfile.TemporaryDirectory() as d:
            tree = os.path.join(d, "a b&c")
            os.makedirs(os.path.join(tree, "scripts"))
            copy = os.path.join(tree, "scripts", "helper-install.sh")
            with open(SCRIPT) as src, open(copy, "w") as dst:
                dst.write(src.read())
            r, calls, _ = self.run_install("", script=copy)
            self.assertEqual(r.returncode, 1)
            self.assertIn("unsupported checkout path", r.stderr)
            self.assertEqual(calls, "")

    def test_needs_root(self):
        r, calls, _ = self.run_install("", uid="1000")
        self.assertEqual(r.returncode, 1)
        self.assertIn("run as root", r.stderr)
        self.assertEqual(calls, "")


if __name__ == "__main__":
    unittest.main()
