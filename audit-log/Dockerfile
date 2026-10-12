# SPDX-FileCopyrightText: 2026 CERN
# SPDX-License-Identifier: GPL-3.0-or-later
FROM python:3.12-slim
COPY auditlog.py /app/auditlog.py
RUN install -d -o nobody -g nogroup /data
USER nobody
EXPOSE 8443
CMD ["python3", "/app/auditlog.py"]
