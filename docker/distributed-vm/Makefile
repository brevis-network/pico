.PHONY: up down logs log-coordinator log-worker build rebuild clean prune ps

# Compile-time environment variables
export RUSTFLAGS="-C target-cpu=native -C target-feature=+avx512f,+avx512ifma,+avx512vl"
export JEMALLOC_SYS_WITH_MALLOC_CONF="retain:true,background_thread:true,metadata_thp:always,dirty_decay_ms:-1,muzzy_decay_ms:-1,abort_conf:true"
# Docker compose environment variables
export DOCKER_BUILDKIT=1

COMPOSE=docker compose

up:
	$(COMPOSE) up --build -d

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

log-coordinator:
	$(COMPOSE) logs -f coordinator

log-worker:
	$(COMPOSE) logs -f worker

build:
	$(COMPOSE) build

rebuild:
	$(COMPOSE) build --no-cache

clean:
	$(COMPOSE) down -v --remove-orphans
	docker image rm -f brevis-multi-machine-builder brevis-multi-machine-coordinator:latest brevis-multi-machine-worker:latest 2>/dev/null || true

prune:
	docker system prune -a --volumes -f

ps:
	$(COMPOSE) ps