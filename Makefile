BIN = xeol
TEMPDIR = ./.tmp
RESULTSDIR = $(TEMPDIR)/results
COVER_REPORT = $(RESULTSDIR)/cover.report
COVER_TOTAL = $(RESULTSDIR)/cover.total
LICENSES_REPORT = $(RESULTSDIR)/licenses.json
LINTCMD = $(TEMPDIR)/golangci-lint run --tests=false --timeout 5m --config .golangci.yaml
GOIMPORTS_CMD = $(TEMPDIR)/gosimports -local github.com/xeol-io
RELEASE_CMD=$(TEMPDIR)/goreleaser release --clean
SNAPSHOT_CMD=$(RELEASE_CMD) --skip-publish --snapshot
VERSION=$(shell git describe --dirty --always --tags)
CHANGELOG := CHANGELOG.md
CHRONICLE_CMD = $(TEMPDIR)/chronicle


# formatting variables
BOLD := $(shell tput -T linux bold)
PURPLE := $(shell tput -T linux setaf 5)
GREEN := $(shell tput -T linux setaf 2)
CYAN := $(shell tput -T linux setaf 6)
RED := $(shell tput -T linux setaf 1)
RESET := $(shell tput -T linux sgr0)
TITLE := $(BOLD)$(PURPLE)
SUCCESS := $(BOLD)$(GREEN)

# the quality gate lower threshold for unit test total % coverage (by function statements)
COVERAGE_THRESHOLD := 34

## Build variables
DISTDIR=./dist
SNAPSHOTDIR=./snapshot
OS=$(shell uname | tr '[:upper:]' '[:lower:]')
SYFT_VERSION=$(shell go list -m all | grep github.com/anchore/syft | awk '{print $$2}')
SNAPSHOT_BIN=$(shell realpath $(shell pwd)/$(SNAPSHOTDIR)/$(OS)-build_$(OS)_amd64_v1/$(BIN))

GOLANGCILINT_VERSION = v1.54.2
BOUNCER_VERSION = v0.4.0
CHRONICLE_VERSION = v0.8.0
GOSIMPORTS_VERSION = v0.3.8
YAJSV_VERSION = v1.4.1
GORELEASER_VERSION = v1.21.2
GLOW_VERSION := v1.5.1
SKOPEO_VERSION := v1.12.0

ifndef TEMPDIR
	$(error TEMPDIR is not set)
endif

ifndef RESULTSDIR
	$(error RESULTSDIR is not set)
endif

ifndef DISTDIR
	$(error DISTDIR is not set)
endif

ifndef SNAPSHOTDIR
	$(error SNAPSHOTDIR is not set)
endif

ifndef VERSION
	$(error VERSION is not set)
endif

define title
    @printf '$(TITLE)$(1)$(RESET)\n'
endef

.PHONY: all
all: clean static-analysis test ## Run all checks (linting, license check, unit, integration, and linux acceptance tests tests)
	@printf '$(SUCCESS)All checks pass!$(RESET)\n'

.PHONY: test
test: unit cli ## Run all tests (unit, and CLI tests)

help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "$(BOLD)$(CYAN)%-25s$(RESET)%s\n", $$1, $$2}'

$(RESULTSDIR):
	mkdir -p $(RESULTSDIR)

$(TEMPDIR):
	mkdir -p $(TEMPDIR)

.PHONY: format
format: ## Auto-format all source code
	$(call title,Running formatters)
	gofmt -w -s .
	$(GOIMPORTS_CMD) -w .
	go mod tidy

.PHONY: bootstrap-tools
bootstrap-tools: $(TEMPDIR)
	GO111MODULE=off GOBIN=$(realpath $(TEMPDIR)) go get -u golang.org/x/perf/cmd/benchstat
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(TEMPDIR)/ $(GOLANGCILINT_VERSION)
	curl -sSfL https://raw.githubusercontent.com/wagoodman/go-bouncer/master/bouncer.sh | sh -s -- -b $(TEMPDIR)/ $(BOUNCER_VERSION)
	curl -sSfL https://raw.githubusercontent.com/anchore/chronicle/main/install.sh | sh -s -- -b $(TEMPDIR)/ $(CHRONICLE_VERSION)
	.github/scripts/goreleaser-install.sh -d -b $(TEMPDIR)/ $(GORELEASER_VERSION)
	# the only difference between goimports and gosimports is that gosimports removes extra whitespace between import blocks (see https://github.com/golang/go/issues/20818)
	GOBIN="$(realpath $(TEMPDIR))" go install github.com/rinchsan/gosimports/cmd/gosimports@$(GOSIMPORTS_VERSION)
	GOBIN="$(realpath $(TEMPDIR))" go install github.com/neilpa/yajsv@$(YAJSV_VERSION)
	GOBIN="$(realpath $(TEMPDIR))" go install github.com/charmbracelet/glow@$(GLOW_VERSION)
	GOBIN="$(realpath $(TEMPDIR))" CGO_ENABLED=0 GO_DYN_FLAGS="" go install -tags "containers_image_openpgp" github.com/containers/skopeo/cmd/skopeo@$(SKOPEO_VERSION)


.PHONY: bootstrap-go
bootstrap-go:
	go mod download

.PHONY: bootstrap
bootstrap: $(TEMPDIR) bootstrap-go bootstrap-tools ## Download and install all go dependencies (+ prep tooling in the ./tmp dir)
	$(call title,Bootstrapping dependencies)

.PHONY: static-analysis
static-analysis: check-go-mod-tidy lint check-licenses

.PHONY: lint
lint: ## Run gofmt + golangci lint checks
	$(call title,Running linters)
	# ensure there are no go fmt differences
	@printf "files with gofmt issues: [$(shell gofmt -l -s .)]\n"
	@test -z "$(shell gofmt -l -s .)"

	# run all golangci-lint rules
	$(LINTCMD)
	@[ -z "$(shell $(GOIMPORTS_CMD) -d .)" ] || (echo "goimports needs to be fixed" && false)

	# go tooling does not play well with certain filename characters, ensure the common cases don't result in future "go get" failures
	$(eval MALFORMED_FILENAMES := $(shell find . | grep -e ':'))
	@bash -c "[[ '$(MALFORMED_FILENAMES)' == '' ]] || (printf '\nfound unsupported filename characters:\n$(MALFORMED_FILENAMES)\n\n' && false)"

.PHONY: lint-fix
lint-fix: ## Auto-format all source code + run golangci lint fixers
	$(call title,Running lint fixers)
	gofmt -w -s .
	$(GOIMPORTS_CMD) -w .
	$(LINTCMD) --fix
	go mod tidy

.PHONY: check-licenses
check-licenses:
	$(call title,Checking for license compliance)
	$(TEMPDIR)/bouncer check ./...

check-go-mod-tidy:
	@ .github/scripts/go-mod-tidy-check.sh && echo "go.mod and go.sum are tidy!"

.PHONY: validate-xeol-db-schema
validate-xeol-db-schema:
	# ensure the codebase is only referencing a single xeol-db schema version, multiple is not allowed
	python3 test/validate-xeol-db-schema.py

.PHONY: unit
unit: $(TEMPDIR) ## Run unit tests (with coverage)
	$(call title,Running unit tests)
	go test -race -coverprofile $(TEMPDIR)/unit-coverage-details.txt $(shell go list ./... | grep -v xeol-io/xeol/test)
	@.github/scripts/coverage.py $(COVERAGE_THRESHOLD) $(TEMPDIR)/unit-coverage-details.txt


.PHONY: ci-release
ci-release: ci-check clean-dist $(CHANGELOG)
	$(call title,Publishing release artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(DISTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	bash -c "\
		$(RELEASE_CMD) \
			--config $(TEMPDIR)/goreleaser.yaml \
			--release-notes <(cat $(CHANGELOG)) \
				 || (cat /tmp/quill-*.log && false)"

	# upload the version file that supports the application version update check (excluding pre-releases)
	.github/scripts/update-version-file.sh "$(DISTDIR)" "$(VERSION)"

.PHONY: ci-check
ci-check:
	@.github/scripts/ci-check.sh

.PHONY: quality
quality: ## Run quality tests
	$(call title,Running quality tests)
	cd test/quality && make

# note: this is used by CI to determine if the install test fixture cache (docker image tars) should be busted
install-fingerprint:
	cd test/install && \
		make cache.fingerprint

install-test: $(SNAPSHOTDIR)
	cd test/install && \
		make

install-test-cache-save: $(SNAPSHOTDIR)
	cd test/install && \
		make save

install-test-cache-load: $(SNAPSHOTDIR)
	cd test/install && \
		make load

install-test-ci-mac: $(SNAPSHOTDIR)
	cd test/install && \
		make ci-test-mac

.PHONY: integration
integration: ## Run integration tests
	$(call title,Running integration tests)
	go test -v ./test/integration

# note: this is used by CI to determine if the integration test fixture cache (docker image tars) should be busted
.PHONY: integration-fingerprint
integration-fingerprint:
	find test/integration/*.go test/integration/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | tee /dev/stderr | md5sum | tee test/integration/test-fixtures/cache.fingerprint && echo "$(INTEGRATION_CACHE_BUSTER)" >> test/integration/test-fixtures/cache.fingerprint

# note: this is used by CI to determine if the cli test fixture cache (docker image tars) should be busted
.PHONY: cli-fingerprint
cli-fingerprint:
	find test/cli/*.go test/cli/test-fixtures/image-* -type f -exec md5sum {} + | awk '{print $1}' | sort | md5sum | tee test/cli/test-fixtures/cache.fingerprint

.PHONY: cli
cli: $(SNAPSHOTDIR) ## Run CLI tests
	chmod 755 "$(SNAPSHOT_BIN)"
	$(SNAPSHOT_BIN) version
	XEOL_BINARY_LOCATION='$(SNAPSHOT_BIN)' \
		go test -count=1 -v ./test/cli

# note: this is used by CI to determine if various test fixture cache should be restored or recreated
# TODO (cphillips) check for all fixtures and individual makefile
fingerprints:
	$(call title,Creating all test cache input fingerprints)

	# for IMAGE integration test fixtures
	cd test/integration/test-fixtures && \
		make cache.fingerprint

	# for INSTALL integration test fixtures
	cd test/install && \
		make cache.fingerprint

	# for CLI test fixtures
	cd test/cli/test-fixtures && \
		make cache.fingerprint

.PHONY: build
build: $(SNAPSHOTDIR) ## Build release snapshot binaries and packages

$(SNAPSHOTDIR):  ## Build snapshot release binaries and packages
	$(call title,Building snapshot artifacts)

	# create a config with the dist dir overridden
	echo "dist: $(SNAPSHOTDIR)" > $(TEMPDIR)/goreleaser.yaml
	cat .goreleaser.yaml >> $(TEMPDIR)/goreleaser.yaml

	# build release snapshots
	$(SNAPSHOT_CMD) --config $(TEMPDIR)/goreleaser.yaml

.PHONY: changelog
changelog: clean-changelog  $(CHANGELOG) ## Generate and show the changelog for the current unreleased version
	$(CHRONICLE_CMD) -vv -n --version-file VERSION > $(CHANGELOG)
	@$(GLOW_CMD) $(CHANGELOG)

$(CHANGELOG):
	$(CHRONICLE_CMD) -vvv > $(CHANGELOG)

.PHONY: validate-syft-release-version
validate-syft-release-version:
	@./.github/scripts/syft-released-version-check.sh

.PHONY: release
release:
	@.github/scripts/trigger-release.sh

.PHONY: clean
clean: clean-dist clean-snapshot  ## Remove previous builds and result reports
	$(call safe_rm_rf_children,$(RESULTSDIR))

.PHONY: clean-dist
clean-dist: clean-changelog
	$(call safe_rm_rf,$(DISTDIR))
	rm -f $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-changelog
clean-changelog:
	rm -f CHANGELOG.md

.PHONY: clean-snapshot
clean-snapshot:
	$(call safe_rm_rf,$(SNAPSHOTDIR))
	rm -f $(TEMPDIR)/goreleaser.yaml

.PHONY: clean-test-cache
clean-test-cache: ## Delete all test cache (built docker image tars)
	find . -type f -wholename "**/test-fixtures/cache/*.tar" -delete

