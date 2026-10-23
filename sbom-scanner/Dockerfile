# SPDX-FileCopyrightText: 2026 CERN
# SPDX-License-Identifier: GPL-3.0-or-later
# grype from source at a pinned version: the Go module checksum database
# (sum.golang.org) vouches for every module it is built from.
FROM golang:1.26 AS grype
ARG GRYPE_VERSION=v0.121.0
RUN CGO_ENABLED=0 GOBIN=/out go install -trimpath github.com/anchore/grype/cmd/grype@${GRYPE_VERSION}

FROM python:3.12-slim
ARG GRYPE_VERSION=v0.121.0
COPY --from=grype /out/grype /usr/local/bin/grype
COPY scanner.py /app/scanner.py
# The database volume inherits this ownership when it is first created.
RUN install -d -o nobody -g nogroup /db
ENV GRYPE_DB_CACHE_DIR=/db TMPDIR=/db/tmp GRYPE_VERSION=${GRYPE_VERSION}
USER nobody
EXPOSE 8080
CMD ["python3", "/app/scanner.py"]
