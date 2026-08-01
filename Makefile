# go-jenkins-mcp — developer targets (FND-002)
# Tier-1: linux/amd64 (+ aarch64 when enabled). No Windows client targets.

export PATH := $(HOME)/.local/go/bin:/usr/local/go/bin:$(PATH)

MODULE      ?= github.com/simonfxr/go-jenkins-mcp
BIN_DIR     ?= bin
DIST_DIR    ?= dist
BINARY      ?= jenkins-mcp
GO          ?= go
GOFLAGS     ?=
GO_TESTFLAGS ?= -count=1

VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DIRTY    ?= $(shell git diff --quiet 2>/dev/null || echo dirty)
GOVER    := $(shell $(GO) version 2>/dev/null | awk '{print $$3}')
BUILDTIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS = -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILDTIME)
# Binary package path (FND-004)
CMD_PKG = ./cmd/jenkins-mcp

# QA-001: short fuzz wall time per target for smoke (not a merge-gate default).
FUZZTIME ?= 2s

.PHONY: help
help:
	@echo "Targets:"
	@echo "  make test       Unit/contract tests (no live Jenkins)"
	@echo "  make test-race  Tests with -race"
	@echo "  make fuzz-smoke QA-001 short native fuzz (opt-in; FUZZTIME=$(FUZZTIME))"
	@echo "  make bench-progressive  PERF-001 progressive log baselines (not in default test)"
	@echo "  make bench-l2-pack      PERF-002 L2 seekable pack baselines (not in default test)"
	@echo "  make perf-regression    QA-003 budget check vs docs/perf-budgets.json (opt-in)"
	@echo "  make build      Build $(BIN_DIR)/$(BINARY) for host"
	@echo "  make lint       gofmt check + go vet"
	@echo "  make vuln       govulncheck (installs if needed)"
	@echo "  make sbom       Generate SPDX SBOM under $(DIST_DIR)/"
	@echo "  make package    Linux tarball (+ optional rpm/deb helpers)"
	@echo "  make package-smoke  PKG-001 offline package script smoke (SKIP_DEB/RPM; not in default test)"
	@echo "  make stdio-smoke    FND-006 offline MCP stdio host-lifecycle smoke (not in default test; Cursor product residual)"
	@echo "  make pilot-evidence  Offline pilot/release evidence under dist/pilot-evidence/ (REL-001/002)"
	@echo "  make live-jenkins-up    Start disposable Jenkins LTS (Docker; not in default test)"
	@echo "  make live-jenkins-test  Compose up + live smoke + down (needs Docker)"
	@echo "  make live-jenkins-down  Stop disposable Jenkins and remove volume"
	@echo "  make ci         lint + test + build (merge gate subset)"
	@echo "  make clean      Remove bin/ and dist/"

.PHONY: test
test:
	$(GO) test $(GOFLAGS) $(GO_TESTFLAGS) ./...

.PHONY: test-race
test-race:
	$(GO) test $(GOFLAGS) $(GO_TESTFLAGS) -race ./...

# QA-001: short native Go fuzz smoke (opt-in; not part of default make test / ci).
# Seed corpora live in f.Add(...) and optional testdata/fuzz/<FuzzName>/ files.
# Crashers are retained by the go tool under testdata/fuzz/ when found.
# Longer runs: go test ./internal/jenkins -run=Fuzz -fuzz=FuzzSanitizeArtifactPath -fuzztime=5m
.PHONY: fuzz-smoke
fuzz-smoke:
	@echo "QA-001 fuzz-smoke FUZZTIME=$(FUZZTIME)"
	$(GO) test $(GOFLAGS) ./internal/jenkins -run=^$$ -fuzz=FuzzSanitizeArtifactPath -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/jenkins -run=^$$ -fuzz=FuzzBuildJobPath -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/jenkins -run=^$$ -fuzz=FuzzNormalizeBaseURL -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/jenkins -run=^$$ -fuzz=FuzzInventoryZip -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/archive -run=^$$ -fuzz=FuzzOpenPack -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/archive -run=^$$ -fuzz=FuzzParseSeekTable -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/archive -run=^$$ -fuzz=FuzzParseIndex -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/redact -run=^$$ -fuzz=FuzzStripControlSequences -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/redact -run=^$$ -fuzz=FuzzRedactText -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/redact -run=^$$ -fuzz=FuzzSanitizeForModel -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/tools -run=^$$ -fuzz=FuzzJobFullName -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/tools -run=^$$ -fuzz=FuzzPolicyTargetFromArgs -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/contracts -run=^$$ -fuzz=FuzzParseJobFullName -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/mutation -run=^$$ -fuzz=FuzzNormalizeParams -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/mutation -run=^$$ -fuzz=FuzzValidateAgainstDefinitions -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/update -run=^$$ -fuzz=FuzzParseManifest -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/update -run=^$$ -fuzz=FuzzLoadLKG -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/policy -run=^$$ -fuzz=FuzzLoadOverlayJSON -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/policy -run=^$$ -fuzz=FuzzDenyJobPrefixMatch -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/auth -run=^$$ -fuzz=FuzzClassifyFallthroughProbe -fuzztime=$(FUZZTIME)
	$(GO) test $(GOFLAGS) ./internal/auth -run=^$$ -fuzz=FuzzParseProtectedResourceMetadata -fuzztime=$(FUZZTIME)
	@echo "fuzz-smoke complete (see docs/phase2-progress.md and CONTRIBUTING.md for longer runs)"

# PERF-001: fixture-only progressive log benchmarks + optional JSON capture.
# Not part of default make test / make ci (benchmarks are opt-in).
# PERF_BASELINE_JSON must be absolute: go test CWD is the package dir.
.PHONY: bench-progressive
bench-progressive:
	@mkdir -p $(CURDIR)/$(DIST_DIR)
	$(GO) test $(GOFLAGS) ./internal/jenkins -bench='Progressive(1MiB|10MiB)' -benchmem -count=1
	PERF_BASELINE_JSON=$(CURDIR)/$(DIST_DIR)/perf-baseline.json \
		$(GO) test $(GOFLAGS) $(GO_TESTFLAGS) ./internal/jenkins -run TestProgressiveBaselineCapture -count=1
	@echo "baseline JSON: $(CURDIR)/$(DIST_DIR)/perf-baseline.json (see docs/perf-baseline.md)"

# PERF-002: L2 seekable multi-frame pack benches + optional JSON capture.
# Not part of default make test / make ci. PERF_L2_BASELINE_JSON must be absolute.
.PHONY: bench-l2-pack
bench-l2-pack:
	@mkdir -p $(CURDIR)/$(DIST_DIR)
	$(GO) test $(GOFLAGS) ./internal/archive -run=^$$ -bench='L2Pack(Build|RangeRead).*(1MiB|10MiB)' -benchmem -count=1
	PERF_L2_BASELINE_JSON=$(CURDIR)/$(DIST_DIR)/perf-l2-baseline.json \
		$(GO) test $(GOFLAGS) $(GO_TESTFLAGS) ./internal/archive -run TestL2PackBaselineCapture -count=1
	@echo "L2 baseline JSON: $(CURDIR)/$(DIST_DIR)/perf-l2-baseline.json (see docs/perf-baseline.md)"

# QA-003: continuous performance regression vs checked-in budgets (opt-in).
# Not part of default make test / make ci (hardware variance; bounded but slower).
# Budgets: docs/perf-budgets.json. Override tolerance: PERF_TOLERANCE_PERCENT=150.
.PHONY: perf-regression
perf-regression:
	@mkdir -p $(CURDIR)/$(DIST_DIR)
	@chmod +x $(CURDIR)/scripts/perf-regression.sh
	PERF_OUT_DIR=$(CURDIR)/$(DIST_DIR) $(CURDIR)/scripts/perf-regression.sh
	@echo "QA-003 report: $(CURDIR)/$(DIST_DIR)/perf-regression-report.json"

.PHONY: build
build:
	@mkdir -p $(BIN_DIR)
	$(GO) build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) $(CMD_PKG)
	@echo "built $(BIN_DIR)/$(BINARY) version=$(VERSION) commit=$(COMMIT) go=$(GOVER) dirty=$(DIRTY) built=$(BUILDTIME)"

.PHONY: lint
lint:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed:"; echo "$$unformatted"; exit 1; fi
	$(GO) vet ./...

.PHONY: vuln
vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

.PHONY: sbom
sbom:
	@mkdir -p $(DIST_DIR)
	$(GO) version -m $(BIN_DIR)/$(BINARY) 2>/dev/null > $(DIST_DIR)/$(BINARY).gomod.txt || true
	$(GO) list -m -json all > $(DIST_DIR)/modules.json
	@echo "SBOM-ish module list: $(DIST_DIR)/modules.json"

.PHONY: package
package: build
	@mkdir -p $(DIST_DIR)
	./scripts/package-linux.sh "$(BIN_DIR)/$(BINARY)" "$(DIST_DIR)" "$(VERSION)" "$(COMMIT)"

.PHONY: package-tarball
package-tarball: package

# PKG-001: offline package script smoke (opt-in; not part of make test / make ci).
# Uses SKIP_DEB=1 SKIP_RPM=1 so hosts without dpkg-deb/rpmbuild still pass.
# Asserts tarball, SHA256SUMS, BUILD_INFO, and secret-free canaries.
.PHONY: package-smoke
package-smoke: build
	@chmod +x $(CURDIR)/scripts/package-linux.sh $(CURDIR)/scripts/package-linux_test.sh
	BIN=$(CURDIR)/$(BIN_DIR)/$(BINARY) \
	PACKAGE_SMOKE_VERSION="$(VERSION)" \
	PACKAGE_SMOKE_COMMIT="$(COMMIT)" \
	$(CURDIR)/scripts/package-linux_test.sh
	@echo "package-smoke complete (see docs/packaging.md)"

# FND-006 Wave 25: offline MCP stdio binary smoke (opt-in; not part of make test / make ci).
# Spawns the real binary over stdio with httptest Jenkins; Initialize + ListTools + CallTool.
# Residual: real Cursor host stdio CI (mcpServers lifecycle) remains open.
.PHONY: stdio-smoke
stdio-smoke: build
	@chmod +x $(CURDIR)/scripts/mcp-stdio-smoke.sh
	BIN=$(CURDIR)/$(BIN_DIR)/$(BINARY) $(CURDIR)/scripts/mcp-stdio-smoke.sh
	@echo "stdio-smoke complete (offline host-lifecycle Done*; Cursor product binary still residual — docs/packaging.md)"

# REL-001/002: offline/local secret-free evidence bundle (version, security self-check,
# gateway qualify, optional doctor/pilot-check when PROFILE= is set).
# PROFILE=      — skip doctor/pilot-check (overall incomplete)
# SKIP_GO_TEST=1 — skip go test summary (default runs ./cmd/jenkins-mcp/)
.PHONY: pilot-evidence
pilot-evidence: build
	@chmod +x $(CURDIR)/scripts/pilot-evidence.sh
	BIN=$(CURDIR)/$(BIN_DIR)/$(BINARY) \
	PROFILE="$(PROFILE)" \
	SKIP_GO_TEST="$(SKIP_GO_TEST)" \
	OUT_ROOT=$(CURDIR)/$(DIST_DIR)/pilot-evidence \
	$(CURDIR)/scripts/pilot-evidence.sh

.PHONY: ci
ci: lint test build

# TST-001: disposable Jenkins LTS live smoke (opt-in; NOT part of make test / make ci).
# Requires Docker Compose v2. Default admin password is disposable "test" only.
COMPOSE_LIVE ?= testdata/jenkins-compose/docker-compose.yml
JENKINS_HOST_PORT ?= 18080
JENKINS_ADMIN_PASSWORD ?= test

.PHONY: live-jenkins-up
live-jenkins-up:
	@command -v docker >/dev/null || { echo "docker required"; exit 1; }
	JENKINS_HOST_PORT=$(JENKINS_HOST_PORT) JENKINS_ADMIN_PASSWORD=$(JENKINS_ADMIN_PASSWORD) \
		docker compose -f $(COMPOSE_LIVE) up -d --build --wait
	@echo "Jenkins listening on http://127.0.0.1:$(JENKINS_HOST_PORT) (token: container /var/jenkins_home/mcp-api-token)"

.PHONY: live-jenkins-down
live-jenkins-down:
	@command -v docker >/dev/null || { echo "docker required"; exit 1; }
	docker compose -f $(COMPOSE_LIVE) down -v --remove-orphans
	@echo "disposable Jenkins stopped; volume removed (credentials destroyed)"

.PHONY: live-jenkins-test
live-jenkins-test:
	@chmod +x $(CURDIR)/scripts/jenkins-live-smoke.sh
	JENKINS_HOST_PORT=$(JENKINS_HOST_PORT) JENKINS_ADMIN_PASSWORD=$(JENKINS_ADMIN_PASSWORD) \
		$(CURDIR)/scripts/jenkins-live-smoke.sh

.PHONY: clean
clean:
	rm -rf $(BIN_DIR) $(DIST_DIR)

.PHONY: version
version:
	@echo "version=$(VERSION) commit=$(COMMIT) dirty=$(DIRTY) go=$(GOVER)"
