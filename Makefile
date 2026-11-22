# SPDX-License-Identifier: Apache-2.0
# Makefile — bits-services: build and lifecycle for the persistent
# supporting-service containers (security-proxy, bits-console backend,
# monitoring). Modeled on cvmfs-testbed. Services are added per phase.

COMPOSE ?= docker compose

.DEFAULT_GOAL := help
.PHONY: help init config build audit-token up down ps status logs unlock secret store-token-key store-build-token-key restricted-sign-key store-admin-token-key credentials-check helper-unit helper-install admin-install admin-up admin-code admin-reset store-up store-gc store-gc-plan store-gc-apply test clean monitoring monitoring-check vmauth-check

# The monitoring stack (Phase 4), started on its own by `make monitoring`.
MON_SERVICES := victoriametrics victorialogs vmauth vmagent cadvisor node-exporter vm-cors runner-sd

help:  ## Print this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  %-17s %s\n", $$1, $$2}'

init:  ## One-time setup: prompts → .env, proxy config, self-signed TLS cert
	bash scripts/setup.sh

config:  ## Validate the compose file
	$(COMPOSE) config

build:  ## Build service images
	$(COMPOSE) build

audit-token:  ## Create the audit-log tokens (secrets/audit_token, secrets/audit-chains/*/token) once
	@mkdir -p -m 700 secrets
	@test -s secrets/audit_token || { umask 022; python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/audit_token; echo "created secrets/audit_token"; }
	@umask 022; test -s secrets/audit-chains/bits-admin/token || { mkdir -p secrets/audit-chains/bits-admin && python3 -c "import secrets; print(secrets.token_urlsafe(32))" > secrets/audit-chains/bits-admin/token && echo "created secrets/audit-chains/bits-admin/token"; } || { echo "cannot write secrets/audit-chains (made by Docker as root?): sudo chown -R $$(id -un) secrets/audit-chains" >&2; exit 1; }
	@test -d $${AUDIT_DATA_DIR:-./data/audit-log} || echo "create the audit-log data dir: sudo install -d -o 65534 -g 65534 $${AUDIT_DATA_DIR:-./data/audit-log}"

up: audit-token vmauth-check  ## Start services (detached), then check signing (a new proxy needs make unlock)
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

helper-unit:  ## Print the bits-admin-helper systemd unit for this checkout
	@sed "s|@DIR@|$(CURDIR)|g" tools/bits-admin-helper.service

helper-install:  ## As root: the helper's group if missing, its unit for this checkout, started
	bash scripts/helper-install.sh

admin-install:  ## As root: the bits-admin group and user if missing, /run/bits-admin, admin-data/
	bash scripts/admin-install.sh

admin-up: audit-token  ## Start bits-admin and wait until it answers on /run/bits-admin/admin.sock
	@COMPOSE="$(COMPOSE)" bash scripts/admin-up.sh

admin-code:  ## Print bits-admin's setup code (at bootstrap, or after admin-reset; each signs in once)
	@cat /run/bits-admin/setup-code

admin-reset:  ## As root, all keys lost: restart bits-admin with a setup code valid 30 minutes
	@test "$$(id -u)" = 0 || { echo "run as root: sudo make admin-reset"; exit 1; }
	install -m 0600 /dev/null /run/bits-admin/reset
	$(COMPOSE) --profile admin restart bits-admin || { rm -f /run/bits-admin/reset; exit 1; }
	@COMPOSE="$(COMPOSE)" bash scripts/admin-up.sh
	@test ! -e /run/bits-admin/reset || { rm -f /run/bits-admin/reset; echo "bits-admin did not take the reset" >&2; exit 1; }
	@echo "the setup code works for 30 minutes: make admin-code"

store-token-key:  ## The store tokens' key: made once (the signing key's passphrase); prints its public key
	python3 tools/unlocking.py store-token-key

store-build-token-key:  ## The build jobs' store tokens' key, as store-token-key
	python3 tools/unlocking.py store-build-token-key

restricted-sign-key:  ## The key bits-store signs /restricted builds with, as store-token-key; prints it for bits
	python3 tools/unlocking.py restricted-sign-key

store-admin-token-key:  ## The key of bits-store's admin tokens (the console's Store page), as store-token-key
	python3 tools/unlocking.py store-admin-token-key

store-up:  ## Build and start bits-store and its TLS proxy (DEPLOYMENT.md, "The store service"), wait until healthy
	$(COMPOSE) --profile bits-store up -d --build --wait bits-store bits-store-proxy

store-gc:  ## Plan a collection of the store's packages no manifest keeps (DEPLOYMENT.md, "The store service"); deletes nothing; ARGS=-gc-list names them
	$(COMPOSE) --profile bits-store run --rm --no-deps bits-store -gc -config /etc/bits-store/config.json -data /var/lib/bits-store $(ARGS)

# ARGS before the plan file's flag: the last of a flag given twice wins.
GC_RUN = $(COMPOSE) --profile bits-store run --rm --no-deps -v $(CURDIR)/gc-plans:/gc$(1) bits-store \
	-gc -config /etc/bits-store/config.json -data /var/lib/bits-store $(ARGS)

store-gc-plan:  ## As store-gc, and write what may go to gc-plans/plan-<time>.json, for review; deletes nothing
	install -d -m 1777 gc-plans
	@f=plan-$$(date -u +%Y%m%dT%H%M%SZ).json; echo "plan: gc-plans/$$f"; \
		$(call GC_RUN,) -gc-out /gc/$$f

store-gc-apply:  ## Delete what PLAN=gc-plans/<file> names and a new plan (the same ARGS) still sweeps; logged in gc-plans/applied.log
	@case "$(PLAN)" in gc-plans/*/*) false ;; gc-plans/plan-*.json) test -f "$(PLAN)" ;; *) false ;; esac || \
		{ echo "PLAN=gc-plans/plan-<time>.json, from make store-gc-plan" >&2; exit 1; }
	bash -o pipefail -c '{ echo "== $$(date -u +%FT%TZ) $(PLAN)"; $(call GC_RUN,:ro) -gc-apply /gc/$(notdir $(PLAN)) 2>&1; } | tee -a gc-plans/applied.log'

test:  ## Functional wiring check (proxy up, backend https/healthz, backend→proxy)
	bash scripts/functional-test.sh

monitoring: vmauth-check  ## Start/refresh only the monitoring stack (signer + backend untouched)
	$(COMPOSE) up -d $(MON_SERVICES)

# vmauth starts only with its users written, and none left with the example's token.
vmauth-check:
	@test -f secrets/vmauth/auth.yml -a -r secrets/vmauth/auth.yml || { echo "secrets/vmauth/auth.yml is missing: DEPLOYMENT.md, Monitoring (vmauth)" >&2; exit 1; }
	@! grep -q 'REPLACE-WITH' secrets/vmauth/auth.yml || { echo "secrets/vmauth/auth.yml still has the example's REPLACE-WITH values" >&2; exit 1; }

monitoring-check:  ## Scrape targets and whether each is up (1) or down (0)
	@port=$$(sed -n "s/^\(export \)\{0,1\}VM_HOST_PORT=['\"]*\([0-9]*\).*/\2/p" .env 2>/dev/null | tail -1); \
	curl -s -G http://localhost:$${port:-8428}/api/v1/query --data-urlencode 'query=up' | \
	  python3 -c 'import sys,json; [print("%s  %-14s %-10s %s" % (r["value"][1], r["metric"].get("job",""), r["metric"].get("role",""), r["metric"].get("instance",""))) for r in sorted(json.load(sys.stdin)["data"]["result"], key=lambda r: r["metric"].get("job",""))]'

clean:  ## Stop services and remove containers + volumes (keeps .env and monitoring data)
	$(COMPOSE) down -v
