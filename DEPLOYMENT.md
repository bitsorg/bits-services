# bits-services — deployment

Status: **stub.** Filled in per phase of the implementation plan
(`bits-services-implementation-plan-2026-09-01.md`).

## Layout

- `docker-compose.yml` — service definitions; `Makefile` wraps the lifecycle
  (`make help`).
- `.env.example` — configuration template (copy to `.env`; no secrets tracked).
- `security-proxy/` — the signer service (Phase 1); vendors `ali-bot` at a
  pinned commit. Not present until Phase 1.

## Networks

- `signer-net` — internal-only; the security-proxy and (Phase 3) the
  bits-console backend attach here. Nothing else may reach the signer.
- `services-net` — backend ↔ public front (web.cern.ch reverse-proxy).
- `monitoring-net` — the monitoring stack (Phase 4). Publishes VictoriaMetrics
  `:8428`, its CORS proxy `:8430` (the two query endpoints only) and vmauth `:8427`
  (the writers' port, a token each); VictoriaLogs is not published.
- The help chat's model is not on a compose network: the backend (and, for the
  embedding model, the worker) reaches Ollama on the host through
  `host.docker.internal` (the docker bridge), see below.

## Configure and run the signer (Phase 1c)

    cp .env.example .env
    # set SECURITY_PROXY_CONFIG_DIR to a host dir you control, then:
    install -d "$SECURITY_PROXY_CONFIG_DIR"
    cp security-proxy/config.sample.json "$SECURITY_PROXY_CONFIG_DIR/config.json"
    make build
    make up          # starts security-proxy on signer-net; no published ports

The agent socket (current port + gate token) lives on the `signer-sockets` named
volume, group `bitssign` (gid 10002), which the backend mounts read-only: it asks
the proxy for its port and token on demand, because both change on every proxy
start and the token also rotates daily. The ingest socket (key push) is in a
container-private tmpfs the backend never sees. All ids are in-image, so there is
no host-uid coupling to arrange.

## Upgrading from a static BITS_SIGN_PROXY_URL/TOKEN

Older deployments copied the proxy's URL and token into `.env` (they went stale on
every proxy restart and within a day of token rotation). To switch, in order:

    make build                                   # proxy image with the bitssign group
    CFG="$(. ./.env; echo "$SECURITY_PROXY_CONFIG_DIR")/config.json"
    sudo python3 -c 'import json,sys; p=sys.argv[1]; c=json.load(open(p)); c["agent_socket_group"]="bitssign"; c["ingest_socket"]="/run/security-proxy-ingest/ingest.sock"; json.dump(c, open(p,"w"), indent=2)' "$CFG"
    make up                                      # recreates proxy + backend
    make unlock                                  # loads the key; drops the old URL/TOKEN from .env

Both config keys must change together (the proxy refuses different socket groups
in one directory), and only after `make build` (the group must exist in the image).

## Key custody — encrypt once, unlock on boot

The signing key is **held in memory only**. It is never written to disk (not even
encrypted), never baked into an image, and is **not persisted** — a container
restart empties the slot, so you re-unlock. The at-rest artifact is a
**passphrase-encrypted PEM on the host** (`secrets/`, gitignored); the container
receives only the in-memory seed, and the passphrase is entered on the host and
never reaches the container.

One-time, to encrypt the passphrase-less key:

    ./tools/encrypt-signing-key.sh /secure/path/signing-key.pem
    # prompts for a new passphrase -> secrets/bits-sign-key.enc.pem (chmod 600)
    # then: passphrase -> password manager; keep an OFFLINE backup of the plaintext
    # (§9a); securely delete the plaintext:  shred -u <plaintext.pem>

After each proxy start (`make up` recreating it, or any restart), unlock:

    make unlock     # prompts for the passphrase, pushes + verifies, then checks signing end to end
    # EXPECTED_KEYID16=<16hex> make unlock   asserts the right key loaded

`make up` and `make status` end with the same check and say "run: make unlock"
when the proxy has no key.

(`tools/migrate-signing-key.sh` is the plaintext-PEM variant used for the initial
A4 migration; `unlock-signing-key.sh` is the steady-state, encrypted flow.)

## Prove the signer by hand (Phase 1e)

Uses a **throwaway** Ed25519 seed — never the production key. All inside the
container, against the ingest socket (container-private tmpfs) and the agent
socket (named volume, shared read-only with the backend):

    # 1. generate a throwaway seed and push it into the 'bits-sign-key' slot
    SEED=$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')
    echo -n "$SEED" | docker compose exec -T security-proxy \
        security-proxy push bits-sign-key --socket /run/security-proxy-ingest/ingest.sock

    # 2. read this route's gate token and the proxy address
    TOKEN=$(docker compose exec -T security-proxy \
        security-proxy-token bits-manifest-sign --socket /run/security-proxy/agent.sock)
    ADDR=$(docker compose exec -T security-proxy \
        security-proxy-token --addr --socket /run/security-proxy/agent.sock)

    # 3. POST sample bytes, then verify the signature against the exported pubkey
    docker compose exec -T security-proxy python3 - "$ADDR" "$TOKEN" <<'PY'
    import sys, json, base64, urllib.request
    addr, token = sys.argv[1], sys.argv[2]
    body = b"hello-bits-sign"
    req = urllib.request.Request(addr + "/sign/bits", data=body,
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/octet-stream"})
    sig = json.load(urllib.request.urlopen(req))
    pubreq = urllib.request.Request(addr + "/sign/bits/pubkey",
        headers={"Authorization": "Bearer " + token})
    pub = json.load(urllib.request.urlopen(pubreq))
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(base64.b64decode(pub["publicKey"])) \
        .verify(base64.b64decode(sig["sig"]), body)
    assert sig["keyid"] == pub["keyid"], "keyid mismatch"
    print("OK: signature verifies; keyid =", sig["keyid"])
    PY

Expected: `401` without the token, `503` before step 1 (slot unprovisioned), and
`OK: signature verifies` after. This is the known-good target Phase 2 automates.

> **Verified on the bits host (Phase 1e):** `make build` → `make up` → push →
> sign → verify passes end-to-end with a throwaway key
> (`OK: signature verifies`). The production key is never used for this check.

## Monitoring (Phase 4)

One VictoriaMetrics for every setup on this host — bits-console, the
cvmfs-testbed and the production publishers — with its data kept under
`MONITORING_DATA_DIR` (default `./data/monitoring`, gitignored), so it outlives
any testbed run. Services: `victoriametrics`, `vmagent`, `cadvisor`,
`node-exporter`, `vm-cors`, `runner-sd`. Images, ports (`8428`, `8430`) and
data layout are those the testbed used, so the bits-console push-agent
(`VM_URL=http://localhost:8428`), the console's `metrics_url` (`:8430`) and the
CI `METRICS_URL` keep working unchanged.

### The Monitoring tab's snapshot (push-agent)

bits-console's push-agent (`monitoring/push-agent.{sh,service,timer}`, on this host)
builds the Monitoring tab's snapshot from VictoriaMetrics every minute. The backend
serves it to signed-in users (`GET /ops/monitoring`) from `MONITORING_SNAPSHOT_DIR`:

    sudo install -d -o gitlab-runner -m 755 /var/lib/bits-monitoring   # push-agent's user
    echo MONITORING_SNAPSHOT_DIR=/var/lib/bits-monitoring >> .env
    make up
    # in /etc/bits/push-agent.env:  SNAPSHOT_DIR=/var/lib/bits-monitoring

push-agent writes there only: its old `GITLAB_URL`, `PROJECT_ID` and `PUSH_TOKEN` lines in
`push-agent.env` are unused, and that GitLab token can be revoked.

### Logs and the writers' port (VictoriaLogs, vmauth)

VictoriaLogs keeps the operational logs (`MONITORING_DATA_DIR/vl`, `VL_RETENTION`,
30 days) and is reached only on monitoring-net. Writers come in through vmauth on
`:8427`, over TLS with the backend's certificate (`TLS_CERT_DIR`), each with its own
token (or basic auth, for systemd-journal-upload), and may only import metrics
(`/api/v1/import/prometheus`) and insert logs (`/insert/...`, always tenant 0:0).
vmauth's own `/metrics`, `/-/reload` and pprof are on `:8426`, not published.
Before `make up` or `make monitoring` (both refuse to start without it):

    install -d -m 700 secrets/vmauth
    cp monitoring/vmauth.yml.example secrets/vmauth/auth.yml   # one user per writer
    openssl rand -hex 32                                       # a token, per user
    install -d -m 777 "${MONITORING_DATA_DIR:-./data/monitoring}/vl"

After it, from another host (H: this host's name in its certificate, T: a writer's token;
add `--cacert` for a self-signed certificate, and `--trust=` for systemd-journal-upload):

    curl -s -o /dev/null -w '%{http_code}\n' --data-binary 'x 1' "https://$H:8427/api/v1/import/prometheus"   # 401
    curl -s -o /dev/null -w '%{http_code}\n' -H "Authorization: Bearer $T" --data-binary 'bits_vmauth_test 1' \
      "https://$H:8427/api/v1/import/prometheus"                                                        # 204
    curl -s -H "Authorization: Bearer $T" -H 'Content-Type: application/stream+json' \
      --data-binary '{"_msg":"vmauth test","host":"'"$(hostname -s)"'"}' "https://$H:8427/insert/jsonline?_stream_fields=host"
    docker compose exec victorialogs wget -qO- 'http://localhost:9428/select/logsql/query?query=vmauth'

Build hosts do not use vmauth: runners may be started on demand, with nothing set up
for them. A build job sends its host's journal to the backend with its CI ID token
(`POST /ops/ci/logs`), and the backend writes it to VictoriaLogs over `logs-net`
(`BITS_LOGS_URL`, default `http://victorialogs:9428`; empty: off), each line named by
the verified token. vmauth's tokens are for the fixed writers (prepub, this host).

A JSON-lines insert needs that content type: curl's default (a form) lets the
body be read as form fields and nothing is stored. A user's routes are only these,
so a token cannot query, delete or snapshot. `docker compose kill -s HUP vmauth`
reloads `secrets/vmauth/auth.yml`. `:8428` stays published until every writer uses
`:8427`; until then it also answers deletes and snapshots on a plain GET, so limit
it to the writers' addresses in the host firewall.

Scrape targets are in `monitoring/scrape.yml`. Other stacks on the host (the
testbed's prepub and Stratum 1s) are scraped through their published ports via
`host.docker.internal`, not by joining their networks, so the testbed can be
torn down and recreated freely; while it is down those scrapes just fail.

The store gauges (`bits_store_*`, the Monitoring page's store bar) come from
bits-store's index, scraped every minute (job `bits-store`, see "The store service");
the push-agent takes those once there are any, else the ones builds with S3 keys push.
Without bits-store the `bits-store` scrape just fails. `BITS_ORCH_METRICS_URL` and
`BITS_ORCH_STORE_GAUGES_S` are no longer read: remove them from `.env`.

### Moving the data over from the testbed (once)

The two stacks publish the same ports, so the testbed's monitoring containers
must go first. They have fixed names, so remove them by name (the testbed's
compose no longer lists them):

    # 1. stop the testbed's monitoring containers
    docker rm -f cvmfs-victoriametrics cvmfs-vmagent cvmfs-cadvisor \
                 cvmfs-node-exporter cvmfs-vm-cors cvmfs-runner-sd

    # 2. copy its VictoriaMetrics data into an EMPTY data dir, before this
    #    stack's VictoriaMetrics has ever started (two trees must not mix)
    cd ~/bits-services
    TESTBED_ROOT=/path/to/testbed/root          # from the testbed's .env
    D="$(. ./.env 2>/dev/null; echo "${MONITORING_DATA_DIR:-./data/monitoring}")"
    docker compose stop victoriametrics 2>/dev/null || true
    sudo ls -A "$D/vm" 2>/dev/null | grep -q . && echo "STOP: $D/vm is not empty"
    # only if that printed nothing:
    sudo install -d -m 777 "$D/vm" "$D/vmagent"
    sudo cp -a "$TESTBED_ROOT/data/monitoring/vm/." "$D/vm/"

    # 3. start it here, then check the scrapes (role="testbed" is the testbed,
    #    role="prepub" the production publishers)
    # (only the monitoring services: the signer is left as it is, key loaded)
    make monitoring
    make monitoring-check

Two things differ from the testbed's stack: retention is 13 months
(`VM_RETENTION`, was 1), and the `prepub` job also scrapes the production
publisher cvmfs-bits-01. The testbed's `data/monitoring/vmagent` held nothing
(no `-remoteWrite.tmpDataPath` was set there), so it is not copied.

Copy `RUNNER_SD_TOKEN` / `RUNNER_SD_PROJECT_ID` / `RUNNER_SD_DESC_REGEX` from the
testbed's `.env` into this one if you used runner discovery there. Once this
stack is confirmed scraping, the monitoring services are removed from the
testbed's compose (its own data dir can then be deleted).

## The orchestrator's shadow certification and outside audit copy (M4)

The worker recomputes every certification the bits-manifests CI signs and
compares it with what was signed; it signs and commits nothing. Set in `.env`:

    BITS_ORCH_MANIFESTS_PROJECT=buncic/bits-manifests
    BITS_ORCH_STORE=b3://<the bucket the certify job validates against>

The read token (`BITS_FORGE_READ_TOKEN`) must reach bits-manifests too (Reporter).
Results are under `GET /ops/certifications`; `GET /ops/certifications/summary?days=14`
counts the sign runs by state, which is the milestone's gate (every one `match`).
The first certification of an architecture hashes all of its store objects once;
later ones hash only the new objects.

The outside copy of the audit chain is the `audit-log` service, for now on this
host (its own container, data directory and internal network; the worker can
only append through its API). Once:

    make audit-token                                          # secrets/audit_token
    sudo install -d -o 65534 -g 65534 data/audit-log          # or AUDIT_DATA_DIR, another disk
    make up

The worker sends the whole chain, then follows it. Check it with
`docker compose exec bits-orchestrator python3 -m console_backend.orch.outside verify`.
On this host it guards against a rewritten or wrongly restored database, not
against someone with root here. To move it to cvmfs-bits-01 later: run
`audit-log/` there (see its README), copy `events.jsonl` over, and set
`BITS_ORCH_AUDIT_URL` and `BITS_ORCH_AUDIT_TOKEN` in `.env`.

## The switch: the orchestrator owns the certified set (M8b)

From the switch the worker keeps the certified set itself (certify adds a
build, decertify and withdrawals take BOMs out), writes the production
manifests (`MANIFESTS/common-manifest-<arch>.json`, numbered), puts
`MANIFESTS/orchestrator.json` in the store, and commits every version of the set
to bits-manifests (the mirror). The bits-manifests CI no longer signs or merges,
and the backend's `/sign*` routes answer 410. Before it: the M8a gate, and a bits
on the runners and with the users that reads the store marker.

1. The mirror's credential: a bits-manifests project access token (Maintainer,
   `api`) that may push to `main`. `tools/service-secrets.py set gitlab-mirror`,
   add the `gitlab-mirror` route of `security-proxy/store-writer.sample.json` to the
   store writer's `config.json` (only the worker reaches it), then `make unlock`.
   In bits-manifests, protect `main` so that only that token's bot may push and
   nobody may merge (the mirror is then the only writer).
2. In bits-manifests, the CI/CD variable `BITS_ORCHESTRATOR_OWNS_SET=true`, *not*
   Protected (merge-request pipelines must see it): the sign job stops, and
   certification merge requests are refused.
3. In `.env`: `BITS_ORCH_OWNS_SET=1` and `BACKEND_SIGNER_SOCKETS=retired-signer-sockets`
   (the backend then cannot reach the signer at all). Then
   `docker compose up -d bits-console-backend bits-orchestrator`.
4. Check: `MANIFESTS/orchestrator.json` is in the store; within a pass every
   architecture of the set is re-signed once (`MANIFESTS/common-manifest-<arch>.json`
   with a `sequence`; then every ten days, well inside its 30-day expiry); each
   certification lands as an `orchestrator: certified set version N` commit in
   bits-manifests; `POST /sign/preapproved` answers 410.
5. Remove `trust_manifest_prefix` from testbed.bits' `defaults-testbed.sh` and,
   once no node reads it, the store's `CANARY/` manifests: they are no longer
   re-signed, and ahead of `MANIFESTS/` they would hide the current ones.

Going back: remove `BITS_ORCH_OWNS_SET` and `BACKEND_SIGNER_SOCKETS` from `.env`,
recreate the two services, and delete the CI/CD variable; bits-manifests holds
the same set (the mirror), so its next pipeline signs what the worker last had.
Then remove the store's marker, which tells bits to leave certification to the
worker (`bits certify` would open no merge request, `bits sign` would refuse):
`bits store rm --raw MANIFESTS/orchestrator.json --force` (after the worker is
recreated: in owned mode it writes the marker again).
Its manifests are unnumbered, which a build node that has read the worker's
numbered ones refuses as older: remove `~/.bits/trust-sequence.json` on the build
nodes when going back.

## The CVMFS status document from the orchestrator

The console's CVMFS tab and Packages page read `cvmfs-status.json` from the
build project's generic package registry. The worker writes it from the builds
it records, in place of a status job in every build pipeline:

1. The ops token (`BITS_FORGE_OPS_TOKEN`) needs Developer on the build project
   and `api` scope, to upload to its package registry.
2. Deploy the bits-console change that removes `bits-prepub-update-status`
   first, so that the worker is the document's only writer. Publishes in
   between are not lost: the worker starts from every build it has recorded.
3. In `.env`: `BITS_ORCH_CVMFS_STATUS=1`, then
   `docker compose up -d bits-orchestrator`.
4. Check: after the next publish, `cvmfs-status.json` has a record with
   `"status": "published"` for it; a `cvmfs_status` step failure shows in
   `GET /ops/events` as `worker.step_failed`.

## The build queue

With the queue, the console's builds wait in the orchestrator and the worker
starts them one per build host, so pending builds never hold the build
project's limit of jobs in active pipelines (which blocks its Pages pipeline):

1. The bits-console change that queues builds gives each host of
   `config/build-hosts.yaml` its `arch` (`x86_64`); add `runner:` to a host
   whose GitLab runner's description is not its `name`.
2. In `.env`: `BITS_ORCH_QUEUE=1`, then
   `docker compose up -d bits-orchestrator bits-console-backend` (the worker
   first, so nothing queued waits for it).
3. Check: `curl -s https://<backend>/healthz` shows `"build_queue": true`; the
   Builds page shows the *Queue* box with the hosts, and a queued build starts
   within a pass (`BITS_ORCH_INTERVAL`). A `dispatch` step failure (no hosts,
   GitLab refusing pipelines) shows in `GET /ops/events` as `worker.step_failed`.

Going back: remove `BITS_ORCH_QUEUE` and recreate both services; the console
starts builds directly again. Builds still queued are not started: queue them
again.

## Who built and approved a file on CVMFS (`bits trace`)

`bits trace <file>` asks the backend which pipeline published the file's package
and who requested and approved it. The orchestrator learns which build published
each path from the prepub nodes' measurement records:

1. In `.env`: `BITS_ORCH_PREPUB_URLS=http://<prepub-1>:8080,http://<prepub-2>:8080`
   (every prepub that publishes), then `docker compose up -d bits-orchestrator
   bits-console-backend` (migration 12 adds the index).
2. The `trace` step reads every build prepub has records of, 50 a pass per
   prepub, so the history is indexed within a few passes; a prepub it cannot
   reach is logged (`trace` in the worker log) and tried again next pass.
3. Check: `bits trace /cvmfs/<repo>/<a package's file>` names the publishing
   pipeline; without the index it says the orchestrator has none.

prepub's measurement records are now the record of who published what: keep
their directory on prepub's persistent disk and in its backups.

## Vulnerability scans

The `sbom-scanner` service (grype) checks every published build's SBOM; the
console's Vulnerabilities page lists the builds, most severe first, and each
build's SBOM report shows its vulnerabilities. Needs bits with the SBOM report
and scans (console-backend migration 13).

1. `.env`: add `scanner` to `COMPOSE_PROFILES` and set
   `BITS_ORCH_SCANNER_URL=http://sbom-scanner:8080`. The host must reach
   `grype.anchore.io`. The database takes about 3.5 GB in the `scanner-db` volume,
   and an update unpacks a second copy beside it: allow 8 GB.
2. `docker compose build sbom-scanner` (builds grype from source, a few minutes),
   then `docker compose up -d sbom-scanner bits-orchestrator bits-console-backend`.
3. The first database download takes a few minutes: `docker compose ps
   sbom-scanner` turns healthy when it is loaded; until then the worker's
   `scan` step waits.
4. The worker scans up to 3 builds a pass, newest first, and every build again
   when the database is newer (daily); while the scanner updates its database
   the step waits. Check: `GET /ops/sbom/scans` lists them, `sbom.scanned`
   events record a change of a build's counts. The findings are kept beside the
   orchestrator database (`sbom-scans/` in its volume), outside its backups: a
   lost copy comes back with the next scan.
5. Who sees what: the Vulnerabilities page and the findings in a build's SBOM
   report are for the admins of the build's community (as its builds are); the
   SBOM itself stays readable by every signed-in user.

Turning it off: `BITS_ORCH_SCANNER_URL=` and restart the worker; the scans
already made stay readable.

## The help chat

The console's Ask page (and the app's) answers questions on using bits, and
explains a failed build, with a local model: Ollama on this host, on its GPU.
The browser asks the backend (`/ops/chat`, like every `/ops` call); the backend
asks Ollama; the worker keeps the docs the answers come from (the bits docs and
the community READMEs, read hourly from GitHub). Needs bits with the help chat
(console-backend migration 24) and rootful docker (`docker info | grep -i
rootless` shows nothing).

Ollama has no authentication. Listening on the docker bridge, it is reachable
from every container on this host's non-internal networks (not only the
backend), which can use, pull or delete models: acceptable while every container
here is ours. It is not reachable from outside the host.

1. **Ollama, on the docker bridge**, which containers reach as
   `host.docker.internal`. Find the bridge's address with `ip -4 addr show
   docker0` (usually `172.17.0.1`; `"bip"` in `/etc/docker/daemon.json` pins
   it), then `sudo systemctl edit ollama` and add:

   ```
   [Unit]
   After=docker.service
   Wants=docker.service

   [Service]
   Environment="OLLAMA_HOST=172.17.0.1:11434"
   Environment="OLLAMA_CONTEXT_LENGTH=16384"
   Environment="OLLAMA_FLASH_ATTENTION=1"
   Environment="OLLAMA_KV_CACHE_TYPE=q8_0"
   Environment="OLLAMA_KEEP_ALIVE=1h"
   ```

   The address exists once docker runs (`After`); `Wants`, not `Requires`, so
   a docker restart does not restart Ollama. Then `sudo systemctl restart
   ollama`. The `ollama` command, run as your user, needs the same address from
   now on: `export OLLAMA_HOST=172.17.0.1:11434` in your shell profile.
2. **The model.** `ollama pull gemma4:12b` (if not there), `ollama run
   gemma4:12b hello`, then `ollama ps`: CONTEXT 16384 and PROCESSOR
   `100% GPU`. A CPU/GPU split means the context does not fit the card: set
   8192 both here (`OLLAMA_CONTEXT_LENGTH`) and as `BITS_CHAT_CONTEXT` below,
   since the backend asks for its own and a different one reloads the model.
3. **The backend reaches it.** `docker compose up -d bits-console-backend` (it
   gets `host.docker.internal`), then

   ```
   docker compose exec bits-console-backend python3 -c "import urllib.request as u; print(u.urlopen('http://host.docker.internal:11434/api/tags', timeout=5).read()[:200])"
   ```

   lists the model. *Connection refused*: Ollama is not listening on the bridge
   (`ss -ltn | grep 11434`). *Timed out* or *no route to host*: the host's
   firewall drops the bridge's traffic to the host (with firewalld, `sudo
   firewall-cmd --get-zone-of-interface=docker0` should say `docker`).
4. **Switch it on.** In `.env`: `BITS_CHAT_URL=http://host.docker.internal:11434`
   (and `BITS_CHAT_CONTEXT` if not 16384), then `docker compose up -d
   bits-orchestrator bits-console-backend`. The worker lists the repositories it
   answers from and reads their markdown files: it must reach `api.github.com`,
   `raw.githubusercontent.com` and `gitlab.cern.ch`. Unauthenticated, GitHub
   allows 60 listings an hour from this host (shared with the backend's catalog
   proxy); `BITS_GITHUB_TOKEN` (public read only, as the backend's) raises that.
5. **Search by meaning** (recommended): questions then find the docs by meaning
   as well as by their words. `ollama pull nomic-embed-text` (about 300 MB of the
   GPU beside the chat model), `BITS_CHAT_EMBED_MODEL=nomic-embed-text` in `.env`,
   then `docker compose up -d bits-orchestrator bits-console-backend`. The worker
   gives each section a vector, a few passes the first time; another model makes
   them again. The worker must reach Ollama too: the check of step 3, run in
   `bits-orchestrator`.
6. **Check:** within a pass, `GET /ops/chat` (signed in) shows `docs` with many
   hundreds of sections (and as many `vectors`, with step 5) and `"available": true`;
   the console's **Ask** page answers, and so does **Explain** on a failed build.
7. **Evaluation**, by hand after a change of model, prompt or context, in the
   backend's container (it has the code and its dependencies):

   ```
   docker compose exec bits-console-backend python3 /src/console-backend/chat-eval/run.py --url http://host.docker.internal:11434 --model gemma4:12b --judge --out /tmp/report.md
   docker compose exec -T bits-console-backend cat /tmp/report.md > report.md
   ```

   Without `--model` it measures only the docs search (seconds); with
   `--judge`, all the cases take a while (two to five model calls each).

**Explain this failure** sends the model, besides what the orchestrator recorded,
what changed since the last successful build of the package on that platform and, for the
community's admins, the end of the failed jobs' logs and of `bits-build.log` or
`bits-publish.log`, read from GitLab when asked (with the backend's GitLab token, as the
worker reads them) and redacted. A model that can think (gemma4 can) thinks first there:
answers take up to twice `BITS_CHAT_TIMEOUT_S`; `BITS_CHAT_EXPLAIN_THINK=0` turns it off.

Nothing of a chat is kept but votes (90 days, `GET /ops/chat/feedback` for
overall admins). Turning it off: `BITS_CHAT_URL=` and `docker compose up -d
bits-orchestrator bits-console-backend`; the Ask page then says the chat is not
set up.

## The store service

bits-store (ADR bits-services 0004) checks store tokens and lets their holders read
and write the store's volumes through short-lived presigned URLs, so no client holds
storage keys. It is built from a release of bits-store, by its tag
(`BITS_STORE_VERSION`, v0.8.10; a tag is never moved: a fix is a new release;
`BITS_STORE_SRC=../bits-store` with `BITS_STORE_VERSION=dev` builds a checkout
instead), and is off unless started:

    install -d -m 0755 config/bits-store
    # config/bits-store/config.json: see bits-store's config.example.json; the
    # test instance's is made by scripts/bits-store/test-instance.py setup DIR
    # the S3 keys its volumes name, as NAME=value lines, in secrets/bits-store.env (600)
    make store-up
    curl -s http://127.0.0.1:8098/health

`make store-up` starts bits-store and `bits-store-proxy`, which terminates TLS in
front of it with the backend's certificate (`TLS_CERT_DIR`) on port 8444
(`BITS_STORE_HTTPS_PORT`). That is the build hosts' way in:
`bits-store+https://<this host>:8444/store`, and `BITS_STORE` in bits-console's CI is
`https://<this host>:8444/store`. Docker publishes the port on every address and
past firewalld's zones, as it does the console's 443: reads of public bindings need
no token, writes do. To narrow who reaches it, publish it on one address
(`BITS_STORE_HTTPS_PORT=ADDRESS:8444`) or add a `DOCKER-USER` rule, and open it in
the network firewall toward the build hosts. The proxy routes each request by its path, so one
name's requests (an upload's start and complete, its first-writer lease) always
reach one instance, never another while it is down: more instances can be listed in
`bits-store/proxy.conf`'s `upstream` later. It allows GET, HEAD and POST, bodies up
to 1 MiB (the bytes go to S3 directly), and waits up to three hours for an answer (a
complete copies a large build in parts; beyond about 150 GiB, longer).

bits-store itself listens on 127.0.0.1:8098 (`BITS_STORE_PORT`), on a network of its
own that reaches its volumes. `/health` answers `503` when a volume's keys cannot
list its bucket (bad keys, a missing bucket), and `bits-store -check`, which
bits-admin runs before applying a configuration, refuses such a volume.
The configuration's `listen` is overridden: the container always listens on :8098.
The service runs as uid 65532, so `config.json` must be readable by others (`chmod
644`; it holds no secret: the keys are in `secrets/bits-store.env`). It reloads
`config.json` when the file changes (a configuration it refuses is logged, the
running one kept); new keys need `make store-up`. Moving from an older setup: the
`BITS_STORE_S3_*` lines go from `.env` into `secrets/bits-store.env`, and
`BITS_STORE_CONFIG` (the file) becomes `BITS_STORE_CONFIG_DIR` (its directory, which
the store must enter: `chmod 755 config/bits-store`). Compose 2.24 or newer reads the
optional key file. bits-admin rewrites `secrets/bits-store.env` (`NAME='value'`), its
keys named `BITS_STORE_...` by the volumes.

bits-store (v0.2.0 or newer: older releases refuse `-data`) keeps an index of what
each bucket holds in the `bits-store-data` volume: each write through it adds its
object, and it lists each bucket against the index at start when new, then daily
(`index_verify` in `config.json`), logging what changed outside it (`index: volume
... missing, changed, extra`). It is a cache: removing the volume costs one listing.
From it, `/metrics` gives the store gauges to vmagent (on `store-metrics-net`; the
proxy answers `404` for it). From v0.3.0 it also reads the BOMs and common manifests,
for the store bar's per-build split: put the public keys that sign the common
manifests (bits' `keys/*.pem`, as PEM text) in `config.json` under
`"manifest_keys"` (bits-admin's Store page), so that only verified ones count.
Without them every common manifest counts and none shows as signed.

`make store-gc` (after `make store-up`, whose index it reads; exit 2 when refused)
plans a collection from the index and deletes nothing: per architecture, the packages
older than 30 days that no BOM and no common manifest lists, not among the 3 newest
builds of their version, not read through bits-store in the last 30 days (nor 10 times
in the last 120), in architectures a verified common manifest lists; `make store-gc
ARGS=-gc-list` names them. Sources (`SOURCES/cache`) are never planned: they are kept
for reference. It refuses while the index may not be the store (`manifest_keys` unset,
an old listing, manifests unread, the common manifests changed since read), while reads
have been counted for less than 30 days (from v0.5.0), or when more than a quarter of an
architecture's packages would go; `bits-store -gc` in bits-store's README.

Deleting is two steps, from bits-store v0.5.3. `make store-gc-plan` (the same `ARGS`)
writes what may go to `gc-plans/plan-<time>.json` (gitignored; none of a refused
volume's) and deletes nothing. Read it, then `make store-gc-apply
PLAN=gc-plans/plan-<time>.json` (the same `ARGS`, within 7 days) plans again and
deletes those of its files the new plan still sweeps, unchanged since (size and ETag,
in the index and the bucket) and not read since; the others stay, each said. The
private bucket's builds are planned too, per group (no manifest certifies them). A
deletion is final; each is appended to `gc-plans/applied.log`. Exit 2: a volume
refused or stopped (or a flag `bits-store` does not know); 1: the plan file not
taken, or a file not deleted. A deleted build asked for later is rebuilt.

## Store tokens

The console gives store tokens to `bits login` and its own pages. They are signed by
the store-token signer, a security-proxy instance of their own that the backend
reaches (it cannot reach the manifest signer after M8b), with a key kept like the
signing key: encrypted under `secrets/`, in the proxy's memory after `make unlock`.

1. `install -d config/store-token-signer`, copy
   `security-proxy/store-token-signer.sample.json` there as `config.json`
   (`sudo chown root:` it, mode 644), then
   `docker compose --profile store-tokens up -d store-token-signer`.
2. `make store-token-key` (the signing key's passphrase): makes the key once and
   prints its public key; put it in the store's `config.json` under `"keys"` as shown.
3. In `.env`: `BITS_STORE_TOKEN_SIGN_ROUTE=bits-store-token-sign`, the store's
   `issuer` and `audience` as `BITS_STORE_TOKEN_ISSUER` and `BITS_STORE_TOKEN_AUDIENCE`,
   and `store-tokens` in `COMPOSE_PROFILES`; then `docker compose up -d
   bits-console-backend` and `make unlock` (it says `pushed slot 'bits-store-token-key'`).

The key lives in the signer's memory only: after the store-token signer alone restarts,
`make unlock` again (the helper does not, while the manifest signer holds its key).
A `bits-store-token-sign` route added to the security proxy's `config.json` earlier
is no longer used: remove it.

Build jobs get their store tokens from the console too (`POST /ops/ci/store-token`,
with the job's CI ID token): for the community and platform of their pipeline, until
the job's ID token expires. They are signed with a key of their own, on a second route
of the same signer:

1. The signer's `config.json` gets the `bits-store-build-token-sign` route of
   `security-proxy/store-token-signer.sample.json`; `docker compose restart
   store-token-signer`.
2. `make store-build-token-key`: makes the key once and prints its public key; put it
   in the store's `config.json` under `"keys"` as shown (`"signer": "build"`).
3. In `.env`: `BITS_STORE_BUILD_TOKEN_SIGN_ROUTE=bits-store-build-token-sign` (and
   `BITS_STORE_BUILD_TOKEN_KID` if not `builds-1`); then `docker compose up -d
   bits-console-backend` and `make unlock` (`pushed slot 'bits-store-build-token-key'`).

Without the route set, the console answers build jobs `503`, and builds go on with
the S3 keys (bits-console's `BITS_STORE` switch off).

### The restricted builds' signing key

Builds that may not be redistributed (`redistributable: sources|none`) are kept by
bits-store in a private bucket under `/restricted`, one folder per community, each
signed when stored with a key of the same signer, on a third route; bits reuses one
only when that signature verifies over the bytes it downloaded, so a tarball swapped
in the bucket is rebuilt. bits-store reaches the signer through its agent socket
(mounted read-only, group `bitssign`) on the internal `restricted-sign-net`:

1. The signer's `config.json` gets the `bits-restricted-sign` route of
   `security-proxy/store-token-signer.sample.json`; `docker compose --profile
   store-tokens up -d store-token-signer` (recreated, on its new network: its keys
   are gone until step 3, and the console's store tokens with them).
2. `make restricted-sign-key`: makes the key once and prints its public key (PEM)
   and key id. bits trusts it saved as a `.pem` under `keys/restricted/` (in bits
   itself, or under `restricted/` of a `$BITS_TRUST_KEYS` directory on the build
   hosts), for these builds only; until then bits neither writes nor reads
   `/restricted`.
3. `docker compose up -d bits-store` (the socket and network) and `make unlock`
   (`pushed slot 'bits-restricted-sign-key'`).
4. The private bucket, `bits-private-store` (no public-read policy; nothing else is
   given its keys), its keys in `secrets/bits-store.env`; bits-store's `config.json`
   (v0.5.2 or later: `gate`, `restricted_signer`) gets, beside what it has, a volume
   for it, the gated binding at `/restricted` and the signer, then `make store-up`:

       "volumes":  {"private": {"endpoint": "https://s3.cern.ch", "bucket": "bits-private-store",
                    "region": "us-east-1", "access_key_env": "BITS_STORE_PRIVATE_ACCESS_KEY",
                    "secret_key_env": "BITS_STORE_PRIVATE_SECRET_KEY"}},
       "bindings": [{"prefix": "/restricted", "volume": "private", "key_prefix": "TARS",
                     "format": "tarballs", "gate": "group", "readers": {"sft": ["lhcb"]}}],
       "restricted_signer": {"agent_socket": "/run/store-token-signer/agent.sock",
                             "route": "bits-restricted-sign", "host": "store-token-signer",
                             "prefix": "/sign/restricted"}

   Each community's builds are its own (`TARS/<community>/<arch>/store/...`);
   `readers` lets the communities listed read another's (here lhcb sft's), none by
   default. bits-store refuses another binding on that bucket, and a gate without a
   signer. Build jobs' store tokens from the console cover `/restricted/<arch>/**`.

The key lives in the signer's memory only: after the signer restarts, `make unlock`
again; meanwhile uploads to `/restricted` answer `503 unsigned` and bits keeps those
builds on their hosts. With the socket, bits-store could also sign store tokens,
which it is the one to check anyway; the backend could sign restricted builds too, as
it can already have bits-store sign any upload with a build token it mints.

A bad restricted build stays signed: withdraw it (bits-store v0.5.4 or later) by its
sha256, its object's `sha256` metadata (`aws s3api head-object` of
`TARS/<community>/<arch>/store/<h2>/<hash>/<file>`), in the binding's `deny`:
`"deny": ["sha256:<hex>"]`, read when `config.json` changes. Reads then find none
(bits rebuilds it) and uploads of those bytes are refused, never signed again. Then
delete the object, so that a rebuild can be stored; hosts that downloaded it keep
their copy until removed there.

### The admin API's key

bits-store's admin API (from v0.6.0: its own listener, never through
bits-store-proxy) takes short admin tokens, for the console's Store page, signed with
a key of their own on a fourth route of the same signer; bits-store takes them for
nothing else. An older bits-store refuses a configuration with an `admin` key:

1. The signer's `config.json` gets the `bits-store-admin-token-sign` route of
   `security-proxy/store-token-signer.sample.json`; `docker compose restart
   store-token-signer` (it reads its routes at start; its keys are gone until `make
   unlock`).
2. `make store-admin-token-key`: makes the key once and prints its public key; put it
   in the store's `config.json` under `"keys"` as shown (`"signer": "admin"`, id
   `admin-1`, or `BITS_STORE_ADMIN_TOKEN_KID`); then `make unlock` (`pushed slot
   'bits-store-admin-token-key'`).
3. In `.env`: `BITS_STORE_ADMIN_URL=http://bits-store-admin:8099` (its admin
   listener, bound to its address on the internal `store-admin-net`, which only the
   backend and the orchestrator share) and
   `BITS_STORE_ADMIN_TOKEN_SIGN_ROUTE=bits-store-admin-token-sign`; then `make
   store-up` and `docker compose up -d bits-console-backend bits-orchestrator`. Until
   both are set the console has no Store page, and the store's problems (from
   v0.8.6: its warnings and errors) are not read: the orchestrator reads them every 5
   minutes, as issues beside the builds' failures (`/ops/issues`, source `store`).
4. The page's history (growth, traffic) comes from this host's VictoriaMetrics, which
   the backend reaches on the internal `metrics-query-net` (`BITS_METRICS_URL`, by
   default `http://victoriametrics:8428`; set it empty to leave the charts out).

From bits-store v0.8.7 (with bits' console backend of the same day) the Store's pages
also list the most read and newest files, the mirrored git repositories, the fetches
from upstream by host and the archives added by hand. Its first start moves the index
to layout 7 (two columns added, at once); an older bits-store started on it drops the
index and lists the buckets anew, and `make store-gc` waits for that first start. An
upload now carries its token's subject in the object's metadata (`bits-by`, as a fill
carries `fetched-by`), seen by whoever reads the object.

From bits-store v0.8.8 (with bits' console backend of the same day) a build's SBOM
report shows overall admins where each package is kept: its build, sources, pip file
and git origin, opening the Store page at each. The backend asks with admin tokens
allowed `POST /_admin/where`, which an older bits-store refuses: the report then
leaves that view out. Nothing to configure.

From bits-store v0.8.9 (with bits of the same day) uploads by people stay possible,
and their uploaders are named. A read by hash says who uploaded the build
(`Bits-Object-By`), and a build that keeps an object someone else uploaded records
them (`stored_by`). The certified manifests then carry each package's approval
chain, signed: who uploaded it, then who certified each BOM listing it. The Store's
Packages page lists the builds uploaded by people, and a CLI pre-approval shows them
and binds who uploaded each. Nothing to configure; with an older bits-store the
builds record `unknown`.

bits-store v0.8.10 lists, in a `pypi` binding's pages, an sdist in every archive pip
unpacks (`.tar.bz2`, `.tar.xz`, ...), not only `.whl`, `.tar.gz` and `.zip`: a release
published only as `.tar.bz2` (storm 0.23) could not be installed through the store.
Nothing to configure.

### Python packages (pip)

From bits-store v0.7.0 a `pypi` binding mirrors a Python package index (PyPI unless
`index` names another, by https): a project's page comes from the index, and each
file is kept in the store on its first read, only with the SHA-256 the index lists,
so pip installs stay the same when the index drops a file or is down. From v0.7.2
it is public, so builds give pip no store token (theirs can write): anyone who
reaches the store reads it, and a first read has the file fetched. Its files are
read by plain URLs, as `/store`'s, so the bucket's public reads must cover `PYPI/`.
bits-store's `config.json` gets, beside what it has, the binding and the files' host
among the trusted ones, else beyond the day's fetch budget a file is only passed on,
not kept; then `make store-up`:

    "bindings": [{"prefix": "/pypi", "volume": "<the volume /store is on>", "key_prefix": "PYPI",
                  "format": "pypi", "public": true}],
    "fetch": {"trusted": [..., "pypi.org", "pythonhosted.org"]}

A check, twice: the second download comes from the bucket.

    pip download --no-deps -d /tmp/pypi-check \
        --index-url "https://<this host>:8444/pypi/simple" six

### Rust crates

From bits-store v0.8.6 a `crates` binding mirrors crates.io's registry for cargo:
each crate a build downloads (a Rust package, or a pip package built from its sdist)
is kept in the store, checked against the checksum crates.io's index lists. bits
gives build containers a `/.cargo/config.toml` pointing cargo there (`store.crates`).
bits-store's `config.json` gets, beside what it has:

    "bindings": [{"prefix": "/crates", "volume": "<the volume /store is on>", "key_prefix": "CRATES",
                  "format": "crates", "public": true, "url": "https://<the store's host and port>/crates"}],
    "fetch": {"trusted": [..., "crates.io"]}

`url` is the binding's address as cargo reaches it (its `config.json` points downloads
there). Being public, its crates are read by plain URLs: `CRATES/` must be public-read
in the bucket, as `PYPI/` is. A check, once the store runs v0.8.6: its
`/crates/index/config.json` names that `url` with `/crates` after it, and
`/crates/index/it/oa/itoa` lists the versions of the crate itoa.

### Git sources

From bits-store v0.8.6 a `git` binding mirrors git repositories: `/git/<host>/<path>`
is `https://<host>/<path>`. Each repository is a partial mirror in the store's data
volume (`bits-store-data`, under `git/`), filled from upstream by what builds ask
for, a tag at once; a tag held never moves. bits sends its clones and fetches there
(`store.git`). bits-store's `config.json` gets, beside what it has:

    "bindings": [{"prefix": "/git", "volume": "<the volume /store is on>", "key_prefix": "GIT",
                  "format": "git", "public": true}],
    "fetch": {"trusted": [..., "github.com", "gitlab.com", "cern.ch"]}

then `make store-up` (a new image: git in it). Repositories of hosts outside
`trusted` count against the day's fetch budgets when first mirrored. A check, twice
(the second from the store):

    git clone --bare --filter=tree:0 https://<this host>:8444/git/github.com/madler/zlib /tmp/z.git
    git -C /tmp/z.git fetch --filter=tree:0 origin refs/tags/v1.3.1:refs/tags/v1.3.1

## Read tokens

Scripts and agents read build failures, builds and the help chat's records (its votes and
the questions the docs did not answer) with a read token instead of a GitLab token (bits
console-backend README, "Read tokens"): GET of those routes only, and a community's token
only that community's.

1. `openssl rand -hex 32`, into `.env` as `BITS_READ_TOKEN_KEY=` (`chmod 600 .env`).
2. `docker compose up -d bits-orchestrator`, then `docker compose up -d bits-console-backend`:
   the worker adds the tables (the chat's unanswered questions and the tokens, migrations
   28 and 29), and until it has, the backend's orchestrator routes answer 503.
3. A new key voids every token issued.
