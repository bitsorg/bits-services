# SPDX-License-Identifier: Apache-2.0
# Makefile — bits-services: build and lifecycle for the persistent
# supporting-service containers (security-proxy, bits-console backend,
# monitoring). Modeled on cvmfs-testbed. Services are added per phase.

COMPOSE ?= docker compose

.DEFAULT_GOAL := help
.PHONY: help init config build audit-token up down ps status logs unlock secret credentials-check test clean monitoring monitoring-check

# The monitoring stack (Phase 4), started on its own by `make monitoring`.
MON_SERVICES := victoriametrics vmagent cadvisor node-exporter vm-cors runner-sd

help:  ## Print this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  %-17s %s\n", $$1, $$2}'

init:  ## One-time setup: prompts → .env, proxy config, self-signed TLS cert
	bash scripts/setup.sh

config:  ## Validate the compose file
	$(COMPOSE) config

build:  ## Build service images
	$(COMPOSE) build

audit-token:  ## Create the audit-log token (secrets/audit_token) once
	@mkdir -p -m 700 secrets
	@test -s secrets/audit_token || { umask 022; python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/audit_token; echo "created secrets/audit_token"; }
	@test -d $${AUDIT_DATA_DIR:-./data/audit-log} || echo "create the audit-log data dir: sudo install -d -o 65534 -g 65534 $${AUDIT_DATA_DIR:-./data/audit-log}"

up: audit-token  ## Start services (detached), then check signing (a new proxy needs make unlock)
	$(COMPOSE) up -d
	-@bash scripts/signing-check.sh --wait 30

down:  ## Stop services
	$(COMPOSE) down

ps:  ## Show service status (compose ps)
	$(COMPOSE) ps

status:  ## At-a-glance: containers + config + cert + health (+ backend logs if down)
	@bash scripts/status.sh

logs:  ## Tail service logs
	$(COMPOSE) logs -f --tail=100

unlock:  ## Decrypt the signing key and the service secrets into the running proxies
	bash scripts/unlock.sh

secret:  ## Store a service secret: make secret SLOT=gitlab-read (prompts the value)
	@test -n "$(SLOT)" || { echo "usage: make secret SLOT=<slot>"; exit 1; }
	python3 tools/service-secrets.py set "$(SLOT)"

credentials-check:  ## GitLab and the store through the credentials proxy, from the worker
	python3 tools/service-secrets.py check

test:  ## Functional wiring check (proxy up, backend https/healthz, backend→proxy)
	bash scripts/functional-test.sh

monitoring:  ## Start/refresh only the monitoring stack (signer + backend untouched)
	$(COMPOSE) up -d $(MON_SERVICES)

monitoring-check:  ## Scrape targets and whether each is up (1) or down (0)
	@curl -s -G http://localhost:8428/api/v1/query --data-urlencode 'query=up' | \
	  python3 -c 'import sys,json; [print("%s  %-14s %-10s %s" % (r["value"][1], r["metric"].get("job",""), r["metric"].get("role",""), r["metric"].get("instance",""))) for r in sorted(json.load(sys.stdin)["data"]["result"], key=lambda r: r["metric"].get("job",""))]'

clean:  ## Stop services and remove containers + volumes (keeps .env and monitoring data)
	$(COMPOSE) down -v
