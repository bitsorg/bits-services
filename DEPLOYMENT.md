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
    sudo install -d "$D/vm" "$D/vmagent"
    sudo cp -a "$TESTBED_ROOT/data/monitoring/vm/." "$D/vm/"

    # 3. start it here, then check the scrapes (role="testbed" is the testbed,
    #    role="prepub" the production publishers)
    # (only the monitoring services: the signer is left as it is, key loaded)
    docker compose up -d victoriametrics vmagent cadvisor node-exporter vm-cors runner-sd
    curl -s -G http://localhost:8428/api/v1/query --data-urlencode 'query=up'

Two things differ from the testbed's stack: retention is 13 months
(`VM_RETENTION`, was 1), and the `prepub` job also scrapes the production
publisher cvmfs-bits-01. The testbed's `data/monitoring/vmagent` held nothing
(no `-remoteWrite.tmpDataPath` was set there), so it is not copied.

Copy `RUNNER_SD_TOKEN` / `RUNNER_SD_PROJECT_ID` / `RUNNER_SD_DESC_REGEX` from the
testbed's `.env` into this one if you used runner discovery there. Once this
stack is confirmed scraping, the monitoring services are removed from the
testbed's compose (its own data dir can then be deleted).

