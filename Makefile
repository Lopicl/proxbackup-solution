VERSION ?= $(shell ./scripts/version.sh)
LDFLAGS := -s -w -X main.version=$(VERSION)
GO      ?= go

.PHONY: all web server agent test e2e clean version

all: web server agent

web:
	cd web && npm ci && npm run build

server:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/pbspc-server-linux-amd64 ./cmd/pbspc-server
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/pbspc-server ./cmd/pbspc-server

agent:
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/pbspc-agent.exe ./cmd/pbspc-agent
	GOOS=windows GOARCH=arm64 CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o bin/pbspc-agent-arm64.exe ./cmd/pbspc-agent

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
