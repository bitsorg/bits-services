# audit-log

The outside copy of the bits orchestrator's audit chain. It runs on a node other
than the orchestrator's (cvmfs-bits-01), so that a rewrite of the orchestrator's
database shows.

The orchestrator's events form a hash chain: each event's hash covers its own
fields and the previous hash. This service keeps the events in one append-only
file, `events.jsonl`, and accepts an event only when it links onto the last one
it holds (the next seq, the right prev_hash, and a hash it recomputes). It has
no route to change or remove an event. The orchestrator asks for the head on
every pass; if the head is not the orchestrator's own event of that seq, the
orchestrator stops sending, records `outside.diverged` and reports it under
`GET /ops/outside`.

## On the orchestrator's host (for now)

bits-services' own `docker-compose.yml` runs this service as `audit-log`, on an
internal network shared only with the worker and vmagent, with its data in
`AUDIT_DATA_DIR` (default `data/audit-log`) and the token from `make audit-token`
(see DEPLOYMENT.md). That guards against a rewritten or wrongly restored
database, not against root on that host; for that it moves to another node:

## Run it on cvmfs-bits-01

    cd audit-log
    cp .env.example .env            # AUDIT_DATA_DIR, the host certificate and key
    make token                      # secrets/audit_token: copy it for the orchestrator now
    make perms                      # the token and data/ to uid 65534, the service's user
    make up
    curl -s https://cvmfs-bits-01.cern.ch:8443/healthz

Serve HTTPS (set `AUDIT_TLS_CERT` / `AUDIT_TLS_KEY`): the token crosses the
network; the key file must be readable by uid 65534 too. Back up `AUDIT_DATA_DIR`; it is the copy that survives losing the
orchestrator's host.

## Connect the orchestrator

In bits-services' `.env` on the orchestrator's host:

    BITS_ORCH_AUDIT_URL=https://cvmfs-bits-01.cern.ch:8443
    BITS_ORCH_AUDIT_TOKEN=<the contents of secrets/audit_token>
    ORCH_AUDIT_CAFILE=/path/to/the/CA/that/signed/the/host/cert   # optional; a host
                                    # path, mounted into the worker as BITS_ORCH_AUDIT_CAFILE

then `docker compose up -d bits-orchestrator`. The worker sends everything from
the first event on, 500 at a time, then follows the chain.

## Check it

    docker compose exec bits-orchestrator python3 -m console_backend.orch.outside status
    docker compose exec bits-orchestrator python3 -m console_backend.orch.outside verify

When it moves here, stop the worker, copy `events.jsonl` from the old data
directory into this one (it is checked when the service starts), start this
service, and point the worker at it.

`verify` walks both copies and reports the first event where they differ. After
an alarm, find the cause first (a database restored from an old copy, or a
rewrite); `outside clear --by <user>` then lets the worker send again.

## API

    POST /v1/events   {"events": [row, ...]}       write token
    GET  /v1/head     {"seq", "hash", "count"}     read or write token
    GET  /v1/events?after=&limit=                   read or write token
    GET  /healthz, /metrics                         no token

`AUDIT_READ_TOKEN` (optional) is a token that can read but not write.

Standard library only; `make test` runs the tests. The hash function must stay
the orchestrator's (`console_backend/orch/events.py`): both test suites check
the same test vector. Publishing the daily head to a transparency log (Rekor)
can be added here later.
