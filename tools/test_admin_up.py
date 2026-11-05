# SPDX-License-Identifier: Apache-2.0
"""Tests for scripts/admin-up.sh, with docker compose, stat and sleep stood in."""

import os
import socket
import socketserver
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "scripts",
                      "admin-up.sh")
# The fake compose logs its arguments; exec fails until the FAKE_ANSWER_AT-th probe.
COMPOSE = '''echo "$*" >> "$FAKE_LOG"
case " $* " in
  *" exec "*) cat > "$FAKE_PROBE"; echo "probe error" >&2; n=$(grep -c " exec " "$FAKE_LOG")
              [ "${FAKE_ANSWER_AT:-0}" -gt 0 ] && [ "$n" -ge "$FAKE_ANSWER_AT" ] ;;
esac
'''
SHIMS = {"stat": 'case "$3" in admin-data) echo "${FAKE_DATA_STAT:-bits-admin:bits-admin}" ;;\n'
                 '  *) echo "${FAKE_STAT:-bits-admin:bits-admin}" ;; esac', "sleep": ":"}


class AdminUpTest(unittest.TestCase):
    def run_up(self, **extra):
        with tempfile.TemporaryDirectory() as d:
            bin_dir = os.path.join(d, "bin")
            os.makedirs(bin_dir)
            for name, body in dict(SHIMS, compose=COMPOSE).items():
                with open(os.path.join(bin_dir, name), "w") as f:
                    f.write("#!/bin/bash\n" + body + "\n")
                os.chmod(os.path.join(bin_dir, name), 0o755)
            log, probe = os.path.join(d, "log"), os.path.join(d, "probe")
            open(log, "w").close()
            env = dict(os.environ, PATH=bin_dir + ":" + os.environ["PATH"], COMPOSE="compose",
                       FAKE_LOG=log, FAKE_PROBE=probe, ADMIN_WAIT_TRIES="4", **extra)
            r = subprocess.run(["bash", SCRIPT], env=env, capture_output=True, text=True)
            with open(log) as f:
                calls = f.read().splitlines()
            text = ""
            if os.path.exists(probe):
                with open(probe) as f:
                    text = f.read()
            return r, calls, text

    def test_waits_until_it_answers(self):
        r, calls, probe = self.run_up(FAKE_ANSWER_AT="3")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(calls[0], "--profile admin up -d bits-admin")
        self.assertEqual(sum(" exec -T bits-admin " in c for c in calls), 3)
        self.assertIn('"/healthz"', probe)
        self.assertIn("BITS_ADMIN_SOCKET", probe)
        self.assertIn("bits-admin is up", r.stdout)

    def test_gives_up_and_shows_the_log(self):
        r, calls, _ = self.run_up()
        self.assertEqual(r.returncode, 1)
        self.assertEqual(sum(" exec " in c for c in calls), 4)
        self.assertEqual(calls[-1], "--profile admin logs --tail 20 bits-admin")
        self.assertIn("did not answer", r.stderr)
        self.assertIn("probe error", r.stderr)

    def run_probe(self, path):
        _, _, probe = self.run_up(FAKE_ANSWER_AT="1")
        env = dict(os.environ, BITS_ADMIN_SOCKET=path)
        return subprocess.run(["python3", "-"], input=probe, env=env, capture_output=True,
                              text=True).returncode

    def test_probe_needs_a_listener_that_answers_200(self):
        class Ok(socketserver.StreamRequestHandler):
            def handle(self):
                self.rfile.readline()
                self.wfile.write(b"HTTP/1.0 200 OK\r\nContent-Length: 0\r\n\r\n")
        with tempfile.TemporaryDirectory() as d:
            live, stale = os.path.join(d, "live.sock"), os.path.join(d, "stale.sock")
            with socketserver.UnixStreamServer(live, Ok) as server:
                server.timeout = 5
                child = os.fork()
                if child == 0:
                    server.handle_request()
                    os._exit(0)
                self.assertEqual(self.run_probe(live), 0)
                os.waitpid(child, 0)
            s = socket.socket(socket.AF_UNIX)
            s.bind(stale)
            s.close()
            self.assertEqual(self.run_probe(stale), 1)

    def test_needs_admin_install_first(self):
        for stat in ({"FAKE_STAT": "root:root"}, {"FAKE_DATA_STAT": "pbuncic:pbuncic"}):
            r, calls, _ = self.run_up(**stat)
            self.assertEqual(r.returncode, 1)
            self.assertEqual(calls, [])
            self.assertIn("sudo make admin-install", r.stderr)


if __name__ == "__main__":
    unittest.main()
