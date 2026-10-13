VERSION ?= $(shell ./scripts/version.sh)
LDFLAGS := -s -w -X main.version=$(VERSION)
GO      ?= go

.PHONY: all web server agent deb dist release test e2e clean version

all: web server agent

web:
	cd web && npm ci && npm run build

server:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/proxbackup-server-linux-amd64 ./cmd/proxbackup-server
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/proxbackup-server ./cmd/proxbackup-server

agent:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/proxbackup-agent.exe ./cmd/proxbackup-agent
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/proxbackup-agent-arm64.exe ./cmd/proxbackup-agent

# Debian packages of the console for installing directly on a PBS host.
deb: web
	for arch in amd64 arm64; do \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/proxbackup-server-linux-$$arch ./cmd/proxbackup-server && \
		$(GO) run ./tools/mkdeb -arch $$arch -version $(VERSION) -binary bin/proxbackup-server-linux-$$arch -out bin || exit 1; \
	done

# Release assets in bin/dist (names are what the auto-updater looks for, see
# internal/update): .debs, standalone server binaries, Windows agents, SHA256SUMS.
DIST := bin/dist
dist: web
	rm -rf $(DIST) && mkdir -p $(DIST)
	for arch in amd64 arm64; do \
		GOOS=linux GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/proxbackup-server-linux-$$arch ./cmd/proxbackup-server && \
		$(GO) run ./tools/mkdeb -arch $$arch -version $(VERSION) -binary $(DIST)/proxbackup-server-linux-$$arch -out $(DIST) && \
		GOOS=windows GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(DIST)/proxbackup-agent-windows-$$arch.exe ./cmd/proxbackup-agent || exit 1; \
	done
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
