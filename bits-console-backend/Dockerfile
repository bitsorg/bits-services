# SPDX-License-Identifier: Apache-2.0
# bits-console backend image — built from the vendored `bits` submodule (which
# holds console-backend/ and bits_helpers/). Non-root; holds no key.
#
# Build context is the `bits` submodule itself (set in docker-compose.yml), for
# the same BuildKit gitlink reason as the security-proxy image. The Dockerfile
# lives outside that context.
#
# Dependencies (network justification, CLAUDE.md): the backend's own pins
# (fastapi/uvicorn/httpx via console-backend/pyproject) plus bits_helpers' runtime
# deps (cryptography, pyyaml, requests) are fetched from PyPI into THIS image only.
# bits itself is NOT pip-installed (its setuptools_scm dynamic version needs git
# metadata absent from the build context); instead bits is put on PYTHONPATH so
# `bits_helpers` imports directly.

FROM python:3.12-slim
WORKDIR /app
COPY . /src
ENV PYTHONPATH=/src \
    PYTHONDONTWRITEBYTECODE=1
RUN pip install --no-cache-dir /src/console-backend cryptography pyyaml requests
USER nobody
EXPOSE 8080
CMD ["uvicorn", "console_backend.main:app", "--host", "0.0.0.0", "--port", "8080"]
