VERSION ?= $(shell ./scripts/version.sh)
# Recursive (=), so recipes that run after `bump` stamp the bumped version.
# Builds from the alpha branch include pre-releases in their updates by default
# (see scripts/prerelease.sh).
PRERELEASE ?= $(shell ./scripts/prerelease.sh)
LDFLAGS = -s -w -X main.version=$(VERSION) -X main.prerelease=$(PRERELEASE)
# Package builds (deb, dist) bump BUILD and TOTAL in VERSION first; plain builds
# and commits don't. BUMP=0 packages the current VERSION as is (the Release
# workflow, which builds the version scripts/release.sh already bumped and tagged).
BUMP ?= 1
GO      ?= go

# Windows version resource (Properties → Details) for the agent exe: go-winres
# writes rsrc_windows_<arch>.syso files that go build links in. The numeric file
# version drops any suffix such as -dev.
WINRES = cd cmd/proxbackup-agent && $(GO) run github.com/tc-hib/go-winres@v0.3.3 simply \
	--arch amd64,arm64 --out rsrc --manifest none \
	--product-name "ProxBackup Agent" --file-description "ProxBackup Agent" \
	--original-filename proxbackup-agent.exe --copyright "AGPL-3.0-or-later" \
	--product-version "$(VERSION)" --file-version "$(firstword $(subst -, ,$(VERSION)))"
AGENT_RSRC = cmd/proxbackup-agent/rsrc_windows_*.syso

.PHONY: all bump web server agent deb dist release test e2e clean version

all: web server agent

bump:
ifeq ($(BUMP),1)
	@echo "package build: version $$(./scripts/version.sh build)"
endif

web:
	cd web && npm ci && npm run build

server:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/proxbackup-server-linux-amd64 ./cmd/proxbackup-server
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/proxbackup-server ./cmd/proxbackup-server

agent:
	$(WINRES)
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/proxbackup-agent.exe ./cmd/proxbackup-agent
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/proxbackup-agent-arm64.exe ./cmd/proxbackup-agent
	rm -f $(AGENT_RSRC)

# Debian packages of the console for installing directly on a PBS host.
deb: bump web
	for arch in amd64 arm64; do \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/proxbackup-server-linux-$$arch ./cmd/proxbackup-server && \
		$(GO) run ./tools/mkdeb -arch $$arch -version $(VERSION) -binary bin/proxbackup-server-linux-$$arch -out bin || exit 1; \
	done

# Release assets in bin/dist (names are what the auto-updater looks for, see
# internal/update): .debs, standalone server binaries, Windows agents, SHA256SUMS.
DIST := bin/dist
dist: bump web
	rm -rf $(DIST) && mkdir -p $(DIST)
	$(WINRES)
	for arch in amd64 arm64; do \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/proxbackup-server-linux-$$arch ./cmd/proxbackup-server && \
		$(GO) run ./tools/mkdeb -arch $$arch -version $(VERSION) -binary $(DIST)/proxbackup-server-linux-$$arch -out $(DIST) && \
		GOOS=windows GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/proxbackup-agent-windows-$$arch.exe ./cmd/proxbackup-agent || exit 1; \
	done
	rm -f $(AGENT_RSRC)
	cd $(DIST) && shasum -a 256 * > SHA256SUMS && cat SHA256SUMS

# Tag HEAD as v$(VERSION) and push the tag; GitHub Actions builds and publishes
# the release (.github/workflows/release.yml). See scripts/release.sh.
release:
	./scripts/release.sh

test:
	$(GO) vet ./...
	GOOS=windows $(GO) vet ./...
	$(GO) test ./...

e2e:
	./scripts/e2e-pbs.sh

version:
	@./scripts/version.sh

clean:
	rm -rf bin
