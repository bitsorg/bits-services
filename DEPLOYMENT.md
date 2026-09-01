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
- `services-net` — backend ↔ public front (web.cern.ch reverse-proxy) and
  monitoring scrape.

## Configure and run the signer (Phase 1c)

    cp .env.example .env
    # set SECURITY_PROXY_CONFIG_DIR to a host dir you control, then:
    install -d "$SECURITY_PROXY_CONFIG_DIR"
    cp security-proxy/config.sample.json "$SECURITY_PROXY_CONFIG_DIR/config.json"
    make build
    make up          # starts security-proxy on signer-net; no published ports

The sockets live on the `signer-sockets` named volume (owned by the in-image
`securityproxy` uid 10001), so there is no host-uid coupling to arrange.

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

After each `make up` (and every restart), unlock:

    ./tools/unlock-signing-key.sh   # prompts for the passphrase, pushes + verifies
    # pass the expected 16-hex key_id as arg 2 to assert the right key loaded

(`tools/migrate-signing-key.sh` is the plaintext-PEM variant used for the initial
A4 migration; `unlock-signing-key.sh` is the steady-state, encrypted flow.)

## Prove the signer by hand (Phase 1e)

Uses a **throwaway** Ed25519 seed — never the production key. All inside the
container, against the ingest/agent sockets on the named volume:

    # 1. generate a throwaway seed and push it into the 'bits-sign-key' slot
    SEED=$(python3 -c 'import os,base64;print(base64.b64encode(os.urandom(32)).decode())')
    echo -n "$SEED" | docker compose exec -T security-proxy \
        security-proxy push bits-sign-key --socket /run/security-proxy/ingest.sock

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
