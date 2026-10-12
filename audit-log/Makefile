# SPDX-FileCopyrightText: 2026 CERN
# SPDX-License-Identifier: GPL-3.0-or-later
-include .env
DATA := $(or $(AUDIT_DATA_DIR),./data)

.PHONY: token perms up down logs test

# A new write token, once. Copy it to the orchestrator's host (BITS_ORCH_AUDIT_TOKEN)
# before `make perms`, which hands it to the service's user.
token:
	@mkdir -p secrets && umask 077 && test -s secrets/audit_token || \
	  python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/audit_token
	@echo "secrets/audit_token: set BITS_ORCH_AUDIT_TOKEN on the orchestrator's host to it"

# The service runs as uid 65534 (nobody): it must read the token and write the data.
perms:
	mkdir -p $(DATA)
	sudo chown 65534:65534 secrets/audit_token $(DATA)

up:
	docker compose up -d --build

down:
	docker compose down

logs:
	docker compose logs --tail 100 audit-log

test:
	python3 -m unittest -v test_auditlog
