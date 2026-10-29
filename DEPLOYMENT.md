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
- `monitoring-net` — the monitoring stack (Phase 4). Publishes only
  VictoriaMetrics `:8428` and its read-only CORS proxy `:8430`.
- The help chat's model is not on a compose network: the backend reaches Ollama
  on the host through `host.docker.internal` (the docker bridge), see below.

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

Scrape targets are in `monitoring/scrape.yml`. Other stacks on the host (the
testbed's prepub and Stratum 1s) are scraped through their published ports via
`host.docker.internal`, not by joining their networks, so the testbed can be
torn down and recreated freely; while it is down those scrapes just fail.

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
5. **Check:** within a pass, `GET /ops/chat` (signed in) shows `docs` with many
   hundreds of sections and `"available": true`; the console's **Ask** page answers,
   and so does **Explain** on a failed build.
6. **Evaluation**, by hand after a change of model, prompt or context, in the
   backend's container (it has the code and its dependencies):

   ```
   docker compose exec bits-console-backend python3 /src/console-backend/chat-eval/run.py --url http://host.docker.internal:11434 --model gemma4:12b --judge --out /tmp/report.md
   docker compose exec -T bits-console-backend cat /tmp/report.md > report.md
   ```

   Without `--model` it measures only the docs search (seconds); with
   `--judge`, all the cases take a while (two to five model calls each).

Nothing of a chat is kept but votes (90 days, `GET /ops/chat/feedback` for
overall admins). Turning it off: `BITS_CHAT_URL=` and `docker compose up -d
bits-orchestrator bits-console-backend`; the Ask page then says the chat is not
set up.
