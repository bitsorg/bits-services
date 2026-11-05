# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/admin-install.sh, with getent, groupadd, systemd-tmpfiles, stat and id stood in."""

import os
import shutil
import subprocess
import tempfile
import unittest

SCRIPTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts")
SHIMS = {
    "id": 'echo "${FAKE_UID:-0}"',
    "getent": 'f=$FAKE_GROUPS; [ "$1" = passwd ] && f=$FAKE_PASSWD; grep -E "^$2:|:$2:" "$f" || exit 2',
    "groupadd": 'echo "$4:x:$3:" >> "$FAKE_GROUPS"; echo "groupadd $*" >> "$FAKE_LOG"',
    "useradd": 'echo "useradd $*" >> "$FAKE_LOG"; echo "${@: -1}:x:$3:" >> "$FAKE_PASSWD"',
    "systemd-tmpfiles": 'echo "systemd-tmpfiles $*" >> "$FAKE_LOG"',
    "stat": 'echo "${FAKE_STAT:-750 bits-admin:bits-admin}"',
    "chown": 'echo "chown $*" >> "$FAKE_LOG"',
}


class AdminInstallTest(unittest.TestCase):
    def run_install(self, groups, uid="0", users="", **extra):
        with tempfile.TemporaryDirectory() as d:
            bin_dir, conf_dir = os.path.join(d, "bin"), os.path.join(d, "tmpfiles.d")
            os.makedirs(bin_dir)
            os.makedirs(conf_dir)
            for name, body in SHIMS.items():
                with open(os.path.join(bin_dir, name), "w") as f:
                    f.write("#!/bin/bash\n" + body + "\n")
                os.chmod(os.path.join(bin_dir, name), 0o755)
            group_file, log = os.path.join(d, "group"), os.path.join(d, "log")
            with open(group_file, "w") as f:
                f.write(groups)
            open(log, "w").close()
            passwd = os.path.join(d, "passwd")
            with open(passwd, "w") as f:
                f.write(users)
            checkout = os.path.realpath(os.path.join(d, "checkout"))
            os.makedirs(os.path.join(checkout, "scripts"))
            for name in ("admin-install.sh", "lib-host.sh"):
                shutil.copy(os.path.join(SCRIPTS, name), os.path.join(checkout, "scripts"))
            self.data_dir = os.path.join(checkout, "admin-data")
            self.link_target = os.path.join(d, "elsewhere")
            os.makedirs(self.link_target, mode=0o755)
            setup = extra.pop("data_setup", None)
            if setup:
                setup(self)
            env = dict(os.environ, PATH=bin_dir + ":" + os.environ["PATH"], FAKE_GROUPS=group_file,
                       FAKE_PASSWD=passwd,
                       FAKE_LOG=log, FAKE_UID=uid, TMPFILES_DIR=conf_dir, ADMIN_RUN_DIR="/run/bits-admin",
                       **extra)
            r = subprocess.run(["bash", os.path.join(checkout, "scripts", "admin-install.sh")],
                               env=env, capture_output=True, text=True)
            conf = os.path.join(conf_dir, "bits-admin.conf")
            text = ""
            if os.path.exists(conf):
                with open(conf) as f:
                    text = f.read()
            with open(log) as f:
                calls = f.read()
            self.data_mode = (oct(os.stat(self.data_dir).st_mode & 0o777)
                              if os.path.isdir(self.data_dir) and not os.path.islink(self.data_dir) else None)
            self.target_mode = oct(os.stat(self.link_target).st_mode & 0o777)
            self.kept = os.path.exists(os.path.join(self.data_dir, "passkeys.json"))
            self.assertEqual([n for n in os.listdir(conf_dir) if n.startswith(".")], [])
            return r, calls, text

    def test_creates_the_group_and_the_directory(self):
        r, calls, conf = self.run_install("docker:x:995:\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("groupadd --system --gid 10003 bits-admin", calls)
        self.assertIn("useradd --system --uid 10003 --gid bits-admin", calls)
        self.assertEqual(conf, "d /run/bits-admin 0750 bits-admin bits-admin -\n")
        self.assertIn("systemd-tmpfiles --create", calls)
        self.assertIn("usermod -aG bits-admin", r.stdout)
        self.assertIn("chown bits-admin:bits-admin .", calls)
        self.assertEqual(self.data_mode, "0o700")

    def test_a_rerun_tightens_the_data_directory_and_keeps_its_files(self):
        def existing(t):
            os.makedirs(t.data_dir, mode=0o755)
            open(os.path.join(t.data_dir, "passkeys.json"), "w").close()
        r, _, _ = self.run_install("bits-admin:x:10003:\n", users="bits-admin:x:10003:\n",
                                   data_setup=existing)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual((self.data_mode, self.kept), ("0o700", True))

    def test_refuses_a_symlinked_data_directory(self):
        r, calls, _ = self.run_install("bits-admin:x:10003:\n", users="bits-admin:x:10003:\n",
                                       data_setup=lambda t: os.symlink(t.link_target, t.data_dir))
        self.assertEqual(r.returncode, 1)
        self.assertIn("not a plain directory; refusing", r.stderr)
        self.assertNotIn("chown", calls)
        self.assertEqual(self.target_mode, "0o755")

    def test_keeps_a_matching_group_and_user(self):
        r, calls, _ = self.run_install("bits-admin:x:10003:pbuncic\n", users="bits-admin:x:10003:\n")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("groupadd", calls)
        self.assertNotIn("useradd", calls)

    def test_refuses_a_uid_taken_by_another_user(self):
        r, calls, conf = self.run_install("bits-admin:x:10003:\n", users="alice:x:10003:\n")
        self.assertEqual(r.returncode, 1)
        self.assertIn("uid 10003 belongs to user alice", r.stderr)
        self.assertEqual((conf, "useradd" in calls), ("", False))

    def test_refuses_mismatched_groups(self):
        for groups, said in (("bits-admin:x:10005:\n", "exists with gid 10005, not 10003"),
                             ("other:x:10003:\n", "gid 10003 belongs to group other")):
            r, calls, conf = self.run_install(groups)
            self.assertEqual(r.returncode, 1)
            self.assertIn(said, r.stderr)
            self.assertEqual((conf, "groupadd" in calls, "tmpfiles" in calls), ("", False, False))

    def test_a_wrong_directory_is_reported(self):
        r, _, _ = self.run_install("bits-admin:x:10003:\n", FAKE_STAT="755 root:root")
        self.assertEqual(r.returncode, 1)
        self.assertIn("not 750 bits-admin:bits-admin", r.stderr)

    def test_needs_root(self):
        r, calls, _ = self.run_install("", uid="1000")
        self.assertEqual((r.returncode, calls), (1, ""))


if __name__ == "__main__":
    unittest.main()
