SHELL := /bin/bash

GO         ?= go
GOLANGCI   ?= golangci-lint
COMPOSE    ?= docker compose
COMPOSE_F  := --env-file deploy/docker/.env -f deploy/docker/docker-compose.yml

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## ' Makefile | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-18s\033[0m %s\n", $$1, $$2}'

# ---------- Go ----------

.PHONY: build
build: ## Build the API binary
	$(GO) build -o bin/api ./cmd/api

.PHONY: build-migrate
build-migrate: ## Build the migration runner
	$(GO) build -o bin/migrate ./cmd/migrate

.PHONY: test
test: ## Run Go tests
	$(GO) test ./... -race -count=1

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI) run ./...

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

# ---------- Web ----------

.PHONY: web-install
web-install: ## Install web deps
	cd web && npm install

.PHONY: web-dev
web-dev: ## Run Vite dev server
	cd web && npm run dev

.PHONY: web-build
web-build: ## Build web for production
	cd web && npm run build

.PHONY: web-test
web-test: ## Run web tests
	cd web && npm test

# ---------- Stack ----------

.PHONY: bootstrap-env
bootstrap-env: ## Generate deploy/docker/.env with random secrets (no overwrite)
	@./scripts/bootstrap-env.sh

.PHONY: install
install: bootstrap-env up ## bootstrap-env + up + migrate + seed (idempotent first-deploy)
	@echo "Waiting for api to be healthy..."
	@for i in $$(seq 1 60); do \
	    h=$$($(COMPOSE) $(COMPOSE_F) ps --format json api 2>/dev/null | $$(which jq) -r '.Health // "starting"' 2>/dev/null | head -1); \
	    [ "$$h" = "healthy" ] && break; sleep 2; \
	done
	$(COMPOSE) $(COMPOSE_F) exec -T api /app/migrate up
	$(COMPOSE) $(COMPOSE_F) exec -T api /app/migrate seed
	@echo ""
	@echo "==> Sign in at http://localhost:$${SMG_HTTP_PORT:-8080}/  (or http://<host>:8080/ from another machine)"
	@echo "    Email:    admin@sentinelmail.local"
	@echo "    Password: see the 'seed: generated admin password:' line above"

.PHONY: up
up: ## Start full Docker stack
	$(COMPOSE) $(COMPOSE_F) up -d --build

.PHONY: down
down: ## Stop full Docker stack
	$(COMPOSE) $(COMPOSE_F) down

.PHONY: logs
logs: ## Tail stack logs
	$(COMPOSE) $(COMPOSE_F) logs -f --tail=200

.PHONY: ps
ps: ## Show stack status
	$(COMPOSE) $(COMPOSE_F) ps

.PHONY: migrate
migrate: ## Run pending database migrations
	$(COMPOSE) $(COMPOSE_F) exec api /app/migrate up

.PHONY: seed
seed: ## Seed default org + admin user
	$(COMPOSE) $(COMPOSE_F) exec api /app/migrate seed

# ---------- Quality gates ----------

.PHONY: check
check: lint test ## Lint + test (run before pushing)
