# The credentials proxy (orchestrator M6)

The backend and the worker used to read their GitLab tokens and the store's keys
from `.env`. With the credentials proxy they hold none. It is a second instance
of the security proxy (same image, `credentials-proxy` in docker-compose.yml)
that keeps the secrets in memory and adds them to requests on the way out:

- **GitLab:** the services send the proxy's gate token as `PRIVATE-TOKEN`, as
  they would a GitLab token; the proxy swaps in the real one. Three routes, one
  token each: `gitlab-read` (pipelines, jobs, logs, bits-manifests),
  `gitlab-ops` (pipeline actions and variables), `gitlab-groups` (the admin
  groups' members).
- **The store:** boto3 talks to the proxy with the gate token as its access key;
  the proxy re-signs every request with the bucket's real keypair (`s3` route).

The gate tokens come from the proxy's agent socket, rotate daily, and are good
for nothing but the proxy. The signer stays as it was: sign-only, no egress.

The secrets are kept in `secrets/service-secrets.enc`, encrypted with a
passphrase (scrypt, AES-256-GCM), and pushed by `make unlock` after every
restart of the proxy. Until then GitLab and store calls answer 503: actions and
the worker wait; logins keep working while the backend's last admin policy lasts
(15 minutes), if the policy is read from GitLab groups.

## Moving over, one step at a time

    install -d config/credentials-proxy
    cp security-proxy/credentials.sample.json config/credentials-proxy/config.json
    $EDITOR config/credentials-proxy/config.json     # the bucket name(s)
    echo 'COMPOSE_PROFILES=credentials' >> .env       # it starts with the rest from now on
    docker compose up -d credentials-proxy bits-console-backend bits-orchestrator
    python3 tools/service-secrets.py import-env  # takes the tokens still in .env
    make unlock                                  # signing key, then these
    make credentials-check                       # each route from the worker

`credentials-check` must print `ok` for every route and the bucket before you go
on: a route whose secret was never pushed answers 503 for ever, and the worker
waits on it silently. With no `BITS_ADMIN_RESOLVE_TOKEN` today, delete the
`gitlab-groups` route from the config instead (admins' groups are then read with
their own tokens, as now). Then, in `.env`:

    BITS_CRED_PROXY_AGENT_SOCKET=/run/credentials-proxy/agent.sock

and `docker compose up -d bits-console-backend bits-orchestrator`. Once all is
well, remove `BITS_FORGE_OPS_TOKEN`, `BITS_FORGE_READ_TOKEN`,
`BITS_ADMIN_RESOLVE_TOKEN`, `BITS_ORCH_S3_ACCESS_KEY_ID` and
`BITS_ORCH_S3_SECRET_ACCESS_KEY` from `.env` and restart the two again. Going
back is setting `BITS_CRED_PROXY_AGENT_SOCKET=` (empty) with the variables back.

## Day to day

    make secret SLOT=gitlab-ops      # a new or rotated value (prompted)
    make unlock                      # pushes it; no service restarts
    python3 tools/service-secrets.py list

The store is publicly readable, and until M8 the worker only reads it. With
`BITS_ORCH_STORE_ANONYMOUS=1` in `.env` it reads with no credentials at all;
then take the `s3` route out of the proxy's config and remove its slots
(`tools/service-secrets.py remove s3-access-<bucket>`, and `s3-secret-<bucket>`).
The route comes back at M8, with a keypair only the worker holds.

A new bucket is a new entry under the `s3` route's `buckets` in the config (a
root-owned file: a changed upstream would replay the keys elsewhere) and its
`s3-access-<bucket>` / `s3-secret-<bucket>` slots.

Both the backend and the worker can use every route of this proxy (its agent
socket hands out all of its gate tokens). So give the store a keypair that can
only read for now; writing `MANIFESTS/` (M8) gets its own, more narrowly held.

## The store writer and worker certification (orchestrator M8a)

From M8a the worker certifies builds itself and writes the signed manifests to
the store; until M8b under `CANARY/` (the canary), which production does not
read, compared with the CI's. Writing needs the store's keypair, and the
credentials proxy is the wrong place for it: its agent socket hands every route
to the backend too, which faces the internet. So the keypair moves to a third
security-proxy instance, `store-writer`, whose socket and network (`store-net`)
only the worker has. The worker also signs: it mounts the signer's agent socket
and joins `signer-net`, as the backend does.

Turning it on, in this order (each step can stay as it is for a while):

1. The worker reads the store anonymously (`BITS_ORCH_STORE_ANONYMOUS=1`, done
   in M6) and the new code is deployed with certification off.
2. The store writer: its config, then `store` in the profiles, then the keys.

       install -d config/store-writer
       cp security-proxy/store-writer.sample.json config/store-writer/config.json
       # .env: COMPOSE_PROFILES=credentials,store
       #       BITS_STORE_WRITER_AGENT_SOCKET=/run/store-writer/agent.sock
       docker compose up -d store-writer bits-orchestrator
       make unlock            # the s3-* slots now go to the store writer
       make credentials-check # "s3 writer <bucket>": ok

3. The credentials proxy loses its `s3` route: remove it from
   `config/credentials-proxy/config.json` (as in credentials.sample.json), then
   `docker compose restart credentials-proxy && make unlock`.
4. Signing, then certification itself:

       # .env: BITS_ORCH_SIGN_PROXY_AGENT_SOCKET=/run/security-proxy/agent.sock
       #       BITS_ORCH_CERTIFY=1
       docker compose up -d --force-recreate bits-orchestrator

   It certifies the builds recorded from then on, never older ones. At most
   `BITS_ORCH_CERTIFY_DAILY_SIGNS` (100) signatures a day; past it, certifying
   pauses with a `worker.step_failed` event. Manifests are valid
   `BITS_ORCH_CERTIFY_VALID_DAYS` (30) days, as the CI's.

Going back: `BITS_ORCH_CERTIFY=` (empty) stops it at once; until M8b nothing
reads what it writes.
