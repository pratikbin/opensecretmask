.PHONY: build test test-integration test-e2e e2e-bins e2e-image lint vuln fix all clean

BIN := osm
E2E_BIN_DIR := tests/e2e/bin
E2E_IMAGE := osm-e2e:dev

build:
	go build -o $(BIN) ./cmd/osm

test:
	go test -race ./...

# test-integration runs the testcontainers-driven integration suite. Builds
# the integration image inline from tests/integration/Dockerfile — no manual
# cross-compile needed.
test-integration:
	go test -tags integration -count=1 -timeout=15m ./tests/integration/...

# e2e-bins cross-compiles the linux/amd64 binaries baked into the e2e image.
e2e-bins:
	mkdir -p $(E2E_BIN_DIR)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	  go build -trimpath -o $(E2E_BIN_DIR)/osm-linux-amd64 ./cmd/osm
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
	  go build -trimpath -o $(E2E_BIN_DIR)/mockupstream-linux-amd64 \
	    ./tests/internal/mockupstream/cmd

# e2e-image builds the osm-e2e:dev container image consumed by tests/e2e.
# Run against DOCKER_HOST for linux/amd64 builds from macOS (see CLAUDE.md).
e2e-image: e2e-bins
	docker build -t $(E2E_IMAGE) -f tests/e2e/Dockerfile tests/e2e

# test-e2e builds the e2e binaries, builds the image, and runs the suite.
# Requires Docker and ANTHROPIC_AUTH_TOKEN to exercise the claude-code paths;
# the mockupstream-driven TestE2E_Run_MaskRoundTrip needs Docker only.
test-e2e: e2e-image
	go test -tags e2e -count=1 -timeout=30m ./tests/e2e/...

lint:
	golangci-lint run ./...
	gosec ./...
	govulncheck ./...

vuln:
	govulncheck ./...

# go fix applies Go 1.26 modernize-style transforms in place.
fix:
	go fix ./...
	gofmt -w .

all: build test lint

clean:
	rm -f $(BIN)
	rm -rf $(E2E_BIN_DIR)
	-docker image rm $(E2E_IMAGE) 2>/dev/null || true
	go clean ./...
