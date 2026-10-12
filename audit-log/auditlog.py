#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 CERN
# SPDX-License-Identifier: GPL-3.0-or-later
"""audit-log: the outside copy of the bits orchestrator's audit chain.

Runs on a node other than the orchestrator's (cvmfs-bits-01). It keeps the
orchestrator's events in one append-only file and accepts an event only when it
links onto the last one it holds: the next seq, its prev_hash equal to that
event's hash, and its own hash recomputed here. It has no way to change or
remove an event, so once an event is here, rewriting the orchestrator's database
shows: the orchestrator compares this service's head with its own chain on every
pass, and `python -m console_backend.orch.outside verify` compares them all.

    POST /v1/events   {"events": [row, ...]}   write token. Rows the service
                      already holds are accepted when identical (a resend);
                      anything that does not link is refused with 409 and the
                      head, and logged.
    GET  /v1/head     {"seq", "hash", "count"}                 read or write token
    GET  /v1/events?after=&limit=   rows after a seq, oldest first
    GET  /healthz     ok, no token
    GET  /metrics     Prometheus text, no token

A row is the orchestrator's events row: seq, ts_ms, kind, subject, actor_kind,
actor_id, cause, payload (the canonical JSON text), prev_hash, hash. The hash
function is the orchestrator's (console_backend/orch/events.py `_digest`); the
two must stay identical, which the shared test vector in test_auditlog.py and in
the orchestrator's tests checks.

Python standard library only. Configuration from the environment:

    AUDIT_DATA         directory of events.jsonl (default /data)
    AUDIT_TOKEN        write token, or AUDIT_TOKEN_FILE a file holding it
    AUDIT_READ_TOKEN   optional read-only token (or AUDIT_READ_TOKEN_FILE)
    AUDIT_LISTEN       host:port (default 0.0.0.0:8443)
    AUDIT_TLS_CERT, AUDIT_TLS_KEY   serve HTTPS when both are set
"""

import hashlib
import hmac
import json
import logging
import os
import ssl
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

GENESIS = "0" * 64
MAX_BODY = 8 << 20
MAX_BATCH = 1000
MAX_PAYLOAD = 64 * 1024
FIELDS = ("seq", "ts_ms", "kind", "subject", "actor_kind", "actor_id", "cause",
          "payload", "prev_hash", "hash")

log = logging.getLogger("audit-log")


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def digest(prev_hash, row):
    """Must equal console_backend.orch.events._digest."""
    body = canonical([row["seq"], row["ts_ms"], row["kind"], row["subject"],
                      row["actor_kind"], row["actor_id"], row["cause"], row["payload"]])
    return hashlib.sha256((prev_hash + body).encode()).hexdigest()


class Refused(Exception):
    pass


def check_row(row):
    if not isinstance(row, dict) or set(row) != set(FIELDS):
        raise Refused("a row has exactly the fields %s" % ", ".join(FIELDS))
    if not isinstance(row["seq"], int) or isinstance(row["seq"], bool) or row["seq"] < 1:
        raise Refused("seq must be a positive integer")
    if not isinstance(row["ts_ms"], int) or isinstance(row["ts_ms"], bool):
        raise Refused("ts_ms must be an integer")
    for f in ("kind", "subject", "actor_kind", "actor_id", "payload", "prev_hash", "hash"):
        if not isinstance(row[f], str):
            raise Refused("%s must be a string" % f)
    if row["cause"] is not None and not isinstance(row["cause"], (str, int)):
        raise Refused("cause must be a string, an integer or null")
    if len(row["payload"]) > MAX_PAYLOAD:
        raise Refused("payload over %d bytes" % MAX_PAYLOAD)


class Log:
    """The append-only file and an index of its rows."""

    def __init__(self, directory):
        os.makedirs(directory, exist_ok=True)
        self.path = os.path.join(directory, "events.jsonl")
        self.lock = threading.Lock()
        self.offsets = []          # offsets[seq - 1] = byte offset of that row
        self.head = (0, GENESIS)
        self.received = 0
        self.refused = 0
        self._load()

    def _load(self):
        if not os.path.exists(self.path):
            open(self.path, "ab").close()
        prev, expect, pos, good = GENESIS, 1, 0, 0
        with open(self.path, "rb") as fh:
            for line in fh:
                if not line.endswith(b"\n"):
                    break                      # a write cut short: truncated below
                try:
                    row = json.loads(line)
                    check_row(row)
                except (ValueError, Refused) as e:
                    raise SystemExit("%s: line %d is not an event (%s); refusing to start"
                                     % (self.path, expect, e))
                if row["seq"] != expect or row["prev_hash"] != prev or digest(prev, row) != row["hash"]:
                    raise SystemExit("%s: the chain breaks at seq %s; refusing to start"
                                     % (self.path, row.get("seq")))
                self.offsets.append(pos)
                pos += len(line)
                good = pos
                prev, expect = row["hash"], expect + 1
        if os.path.getsize(self.path) != good:
            log.warning("dropping an incomplete last line of %s", self.path)
            with open(self.path, "r+b") as fh:
                fh.truncate(good)
        self.head = (expect - 1, prev)
        log.info("loaded %d events, head %s %s", expect - 1, *self.head)

    def _row(self, seq):
        with open(self.path, "rb") as fh:
            fh.seek(self.offsets[seq - 1])
            return json.loads(fh.readline())

    def append(self, rows):
        """Append *rows*; a prefix the log already holds must be identical.
        Returns how many were new."""
        if not isinstance(rows, list) or not rows or len(rows) > MAX_BATCH:
            raise Refused("events must be a list of 1 to %d rows" % MAX_BATCH)
        for r in rows:
            check_row(r)
        with self.lock:
            seq, prev = self.head
            new = []
            for r in rows:
                if r["seq"] <= seq and not new:
                    if r["seq"] < 1 or self._row(r["seq"]) != r:
                        raise Refused("event %d differs from the one held" % r["seq"])
                    continue
                expect_seq = (new[-1]["seq"] if new else seq) + 1
                expect_prev = new[-1]["hash"] if new else prev
                if r["seq"] != expect_seq:
                    raise Refused("expected seq %d, got %d" % (expect_seq, r["seq"]))
                if r["prev_hash"] != expect_prev:
                    raise Refused("event %d does not link onto %s" % (r["seq"], expect_prev))
                if digest(expect_prev, r) != r["hash"]:
                    raise Refused("event %d's hash does not match its content" % r["seq"])
                new.append(r)
            if not new:
                return 0
            pos = os.path.getsize(self.path)
            lines = [(canonical({k: r[k] for k in FIELDS}) + "\n").encode() for r in new]
            try:
                with open(self.path, "ab") as fh:
                    fh.write(b"".join(lines))
                    fh.flush()
                    os.fsync(fh.fileno())
            except OSError:
                # A full disk or an I/O error: leave the file as it was, so a
                # resend appends whole lines and the next start still loads.
                with open(self.path, "r+b") as fh:
                    fh.truncate(pos)
                raise
            for line in lines:
                self.offsets.append(pos)
                pos += len(line)
            self.head = (new[-1]["seq"], new[-1]["hash"])
            self.received += len(new)
            return len(new)

    def after(self, seq, limit):
        with self.lock:
            last = self.head[0]
        out = []
        for s in range(max(0, seq) + 1, min(last, max(0, seq) + limit) + 1):
            out.append(self._row(s))
        return out


def _secret(name):
    path = os.environ.get(name + "_FILE")
    if path:
        with open(path) as fh:
            return fh.read().strip()
    return os.environ.get(name, "")


class Handler(BaseHTTPRequestHandler):
    server_version = "audit-log"
    timeout = 30                    # per socket operation: a silent client is dropped
    log_obj = None
    write_token = ""
    read_token = ""

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    def _send(self, status, obj, ctype="application/json"):
        body = obj if isinstance(obj, bytes) else json.dumps(obj).encode()
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _token_ok(self, write):
        got = self.headers.get("Authorization", "")
        got = got[7:] if got.startswith("Bearer ") else ""
        ok = [self.write_token] + ([] if write else [self.read_token])
        return any(t and hmac.compare_digest(got.encode(), t.encode()) for t in ok)

    def _head(self):
        seq, h = self.log_obj.head
        return {"seq": seq, "hash": h, "count": seq}

    def do_GET(self):
        url = urlparse(self.path)
        if url.path == "/healthz":
            return self._send(200, {"ok": True})
        if url.path == "/metrics":
            lg = self.log_obj
            text = ("# TYPE audit_log_head_seq gauge\naudit_log_head_seq %d\n"
                    "# TYPE audit_log_received_total counter\naudit_log_received_total %d\n"
                    "# TYPE audit_log_refused_total counter\naudit_log_refused_total %d\n"
                    % (lg.head[0], lg.received, lg.refused))
            return self._send(200, text.encode(), "text/plain; version=0.0.4")
        if not self._token_ok(write=False):
            return self._send(401, {"error": "a bearer token is required"})
        if url.path == "/v1/head":
            return self._send(200, self._head())
        if url.path == "/v1/events":
            q = parse_qs(url.query)
            try:
                after = int((q.get("after") or ["0"])[0])
                limit = max(1, min(int((q.get("limit") or ["1000"])[0]), 1000))
            except ValueError:
                return self._send(400, {"error": "after and limit are integers"})
            return self._send(200, {"events": self.log_obj.after(after, limit)})
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        if urlparse(self.path).path != "/v1/events":
            return self._send(404, {"error": "not found"})
        if not self._token_ok(write=True):
            return self._send(401, {"error": "the write token is required"})
        try:
            n = int(self.headers.get("Content-Length") or "0")
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            return self._send(413, {"error": "body over %d bytes" % MAX_BODY})
        try:
            body = json.loads(self.rfile.read(n) or b"{}")
            rows = body.get("events") if isinstance(body, dict) else None
            added = self.log_obj.append(rows)
        except (ValueError, Refused) as e:
            self.log_obj.refused += 1
            log.error("refused a batch from %s: %s", self.address_string(), e)
            return self._send(409, {"error": str(e), "head": self._head()})
        except OSError as e:
            log.error("cannot write %s: %s", self.log_obj.path, e)
            return self._send(503, {"error": "the log cannot be written now"})
        return self._send(200, {"accepted": added, "head": self._head()})


def make_server(directory, listen, write_token, read_token="", cert=None, key=None):
    if not write_token:
        raise SystemExit("set AUDIT_TOKEN (or AUDIT_TOKEN_FILE)")
    host, _, port = listen.rpartition(":")
    handler = type("H", (Handler,), {"log_obj": Log(directory), "write_token": write_token,
                                      "read_token": read_token})
    ctx = None
    if cert and key:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(cert, key)
    return Server((host or "0.0.0.0", int(port)), handler, ctx)


class Server(ThreadingHTTPServer):
    """TLS is set up in each connection's own thread, with a timeout, so a client
    that connects and says nothing cannot hold up the others."""
    daemon_threads = True

    def __init__(self, address, handler, ctx=None):
        self.ctx = ctx
        super().__init__(address, handler)

    def finish_request(self, request, client_address):
        request.settimeout(30)
        if self.ctx is not None:
            try:
                request = self.ctx.wrap_socket(request, server_side=True)
            except (ssl.SSLError, OSError) as e:
                log.info("TLS handshake with %s failed: %s", client_address[0], e)
                return
            try:
                super().finish_request(request, client_address)
            finally:
                request.close()
            return
        super().finish_request(request, client_address)


def main():
    logging.basicConfig(level=logging.INFO, stream=sys.stdout,
                        format="%(asctime)s %(levelname)s %(name)s %(message)s")
    srv = make_server(os.environ.get("AUDIT_DATA", "/data"),
                      os.environ.get("AUDIT_LISTEN", "0.0.0.0:8443"),
                      _secret("AUDIT_TOKEN"), _secret("AUDIT_READ_TOKEN"),
                      os.environ.get("AUDIT_TLS_CERT"), os.environ.get("AUDIT_TLS_KEY"))
    log.info("audit-log listening on %s:%s", *srv.server_address[:2])
    srv.serve_forever()


if __name__ == "__main__":
    main()
