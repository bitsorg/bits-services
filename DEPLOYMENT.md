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

## Prove the signer by hand (Phase 1e)

The exact commands to push a throwaway key into the running proxy and verify a
signature from its `sign` route are recorded here once the service lands. The
production signing key is never used for this check.
