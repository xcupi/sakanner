# sakanner -- convenience targets. See README.md for the equivalent raw
# commands; these just wrap them.

LAB_PIDFILE := /tmp/sakanner-labserver.pid
LAB_LOGFILE := /tmp/sakanner-labserver.log

.PHONY: build test lab-up lab-up-phase3 lab-down lab-reset lab-status lab-test lab-test-phase3 lab-docker-up lab-docker-down

build:
	go build -o bin/scanner ./cmd/scanner

test:
	go test ./... -race

# --- Phase 2 Test Laboratory (see docs/phase-2-test-lab.md) ---------------
#
# lab-up/lab-down/lab-reset drive the Go-native harness (lab), which
# needs nothing beyond the Go toolchain -- no Docker, no root. This is the
# lab configuration actually verified in this repo; see
# docs/phase-2-test-lab.md for why. lab-docker-up/lab-docker-down are the
# Docker Compose profile (lab/docker-compose.yml), provided per the
# project's requirements but NOT verified by execution here since Docker
# is not installed on the machine this was authored on -- see that doc's
# "Known limitations" before relying on it.

lab-up:
	@if [ -f $(LAB_PIDFILE) ] && kill -0 $$(cat $(LAB_PIDFILE)) 2>/dev/null; then \
		echo "lab already running (pid $$(cat $(LAB_PIDFILE)))"; \
	else \
		go build -o bin/labserver ./lab/cmd/labserver; \
		nohup ./bin/labserver > $(LAB_LOGFILE) 2>&1 & echo $$! > $(LAB_PIDFILE); \
		sleep 1; \
		echo "lab started (pid $$(cat $(LAB_PIDFILE))); addresses in $(LAB_LOGFILE)"; \
		cat $(LAB_LOGFILE); \
	fi

lab-up-phase3:
	@if [ -f $(LAB_PIDFILE) ] && kill -0 $$(cat $(LAB_PIDFILE)) 2>/dev/null; then \
		echo "lab already running (pid $$(cat $(LAB_PIDFILE)))"; \
	else \
		go build -o bin/labserver ./lab/cmd/labserver; \
		LAB_PHASE3=1 nohup ./bin/labserver > $(LAB_LOGFILE) 2>&1 & echo $$! > $(LAB_PIDFILE); \
		sleep 1; \
		echo "lab started with Phase 3 fixtures (pid $$(cat $(LAB_PIDFILE))); addresses in $(LAB_LOGFILE)"; \
		cat $(LAB_LOGFILE); \
	fi

lab-down:
	@if [ -f $(LAB_PIDFILE) ]; then \
		kill $$(cat $(LAB_PIDFILE)) 2>/dev/null || true; \
		rm -f $(LAB_PIDFILE); \
		echo "lab stopped"; \
	else \
		echo "lab is not running"; \
	fi

lab-reset: lab-down lab-up

lab-status:
	@if [ -f $(LAB_PIDFILE) ] && kill -0 $$(cat $(LAB_PIDFILE)) 2>/dev/null; then \
		echo "lab running (pid $$(cat $(LAB_PIDFILE)))"; \
	else \
		echo "lab is not running"; \
	fi

lab-test:
	go test ./lab/... -race -v

# Phase 3 Security Test Laboratory only (see docs/phase-3-test-lab.md).
# A subset of lab-test's own suite -- run standalone for a faster inner
# loop while iterating on Phase 3 fixtures specifically.
lab-test-phase3:
	go test ./lab/... -race -v -run '^TestPhase3Lab|^TestCompareFindings|^TestLoadVulnGroundTruth'

lab-docker-up:
	docker compose -f lab/docker-compose.yml up -d

lab-docker-down:
	docker compose -f lab/docker-compose.yml down -v
