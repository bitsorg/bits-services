# bits-services

Supporting service containers for running BITS.

`bits-services` holds the **persistent, shared** services of the bits ecosystem —
the security-proxy (manifest signer), the bits-console backend, and the
monitoring stack — that outlive any single test run. It is modeled on
`cvmfs-testbed` (Makefile + docker-compose): where cvmfs-testbed owns the
*ephemeral* per-test topology, bits-services owns the *long-lived* services.

Design and build-out: `bits-signing-approval-design-*.md` and
`bits-services-implementation-plan-*.md`.

## Quick start

    cp .env.example .env      # fill in host paths
    make help                 # list targets
    make build && make up     # build images and start (as services land)

## Services

| Service              | Phase | Notes                                        |
|----------------------|-------|----------------------------------------------|
| security-proxy       | 1     | signing key in memory only; internal network |
| bits-console backend | 3     | relying party; the only client of the proxy  |
| monitoring           | 4     | extracted from cvmfs-testbed                 |

The security-proxy vendors `ali-bot/security-proxy` unforked, at a pinned
commit; the signing key is never baked into an image — it is pushed into the
running proxy over its ingest socket and held only in memory.

## License

Apache-2.0. See `LICENSE`, `COPYRIGHT`, `NOTICE`.
