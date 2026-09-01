# SPDX-License-Identifier: Apache-2.0
# security-proxy image — the bits manifest signer (ali-bot/security-proxy),
# vendored UNFORKED at the pinned submodule commit. Non-root; no key baked.
#
# Dependencies (network justification, CLAUDE.md): installed with `pip install .`
# from the pinned submodule, which uses the exact direct-dependency versions the
# package pins in its pyproject (fastapi/uvicorn/httpx/cryptography/websockets)
# plus their transitive deps. The package's own requirements.lock is a
# macOS/py3.14 hash-locked file and will NOT install on linux — a linux hash-lock
# is a later hardening step. Wheels are fetched from PyPI into THIS image only
# (reproducible at the direct-pin level), never onto the host.

FROM python:3.12-slim AS build
WORKDIR /src
COPY ali-bot/security-proxy/ /src/
RUN python -m venv /opt/security-proxy/venv \
 && /opt/security-proxy/venv/bin/pip install --no-cache-dir --upgrade pip \
 && /opt/security-proxy/venv/bin/pip install --no-cache-dir .

FROM python:3.12-slim
# System, non-login runtime user. Sockets live under /run/security-proxy, which
# is a mounted volume (writable); the rest of the fs is read-only at runtime.
RUN useradd --system --uid 10001 --home-dir /var/lib/security-proxy \
      --shell /usr/sbin/nologin securityproxy \
 && mkdir -p /run/security-proxy /etc/security-proxy /var/lib/security-proxy \
 && chown securityproxy:securityproxy /run/security-proxy /var/lib/security-proxy
COPY --from=build /opt/security-proxy/venv /opt/security-proxy/venv
ENV PATH="/opt/security-proxy/venv/bin:$PATH" \
    PYTHONDONTWRITEBYTECODE=1
USER securityproxy
# Config is mounted at runtime (never baked). The Ed25519 signing key is pushed
# over the ingest socket into the "bits-sign-key" slot and held only in memory.
ENTRYPOINT ["security-proxy"]
CMD ["--config", "/etc/security-proxy/config.json"]
