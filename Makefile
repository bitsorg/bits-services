# SPDX-License-Identifier: Apache-2.0
# Makefile — bits-services: build and lifecycle for the persistent
# supporting-service containers (security-proxy, bits-console backend,
# monitoring). Modeled on cvmfs-testbed. Services are added per phase.

COMPOSE ?= docker compose

.DEFAULT_GOAL := help
.PHONY: help init config build up down ps logs unlock test clean

help:  ## Print this help
	@grep -E '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) | \
	  awk 'BEGIN{FS=":.*?## "}{printf "  %-8s %s\n", $$1, $$2}'

init:  ## One-time setup: prompts → .env, proxy config, self-signed TLS cert
	bash scripts/setup.sh

config:  ## Validate the compose file
	$(COMPOSE) config

build:  ## Build service images
	$(COMPOSE) build

up:  ## Start services (detached)
	$(COMPOSE) up -d

down:  ## Stop services
	$(COMPOSE) down

ps:  ## Show service status
	$(COMPOSE) ps

logs:  ## Tail service logs
	$(COMPOSE) logs -f --tail=100

unlock:  ## Decrypt the signing key into the running proxy + wire its URL/token into .env
	bash scripts/unlock.sh

test:  ## Functional wiring check (proxy up, backend https/healthz, backend→proxy)
	bash scripts/functional-test.sh

clean:  ## Stop services and remove containers + volumes (keeps .env)
	$(COMPOSE) down -v
