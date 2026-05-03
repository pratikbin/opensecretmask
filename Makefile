.PHONY: build test test-integration test-all test-e2e e2e-image e2e-binary lint vet sec fmt clean

E2E_IMAGE ?= osm-e2e:dev

build:
	go build -trimpath -ldflags="-s -w" -o bin/osm ./cmd/osm
test:
	go test -race -count=1 ./...
test-integration:
	go test -race -count=1 -tags=integration ./tests/integration/...
test-all:
	go test -race -count=1 -tags=integration ./...

# end-to-end tests drive a real claude-code CLI inside a docker container
# with osm hooks installed. Requires a docker daemon (DOCKER_HOST may
# point at a remote linux/amd64 host) and ANTHROPIC_AUTH_TOKEN in env.
e2e-binary:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
	    -o tests/e2e/bin/osm-linux-amd64 ./cmd/osm
e2e-image: e2e-binary
	docker build -t $(E2E_IMAGE) tests/e2e
test-e2e: e2e-image
	go test -count=1 -tags=e2e -timeout=15m ./tests/e2e/...

lint:
	golangci-lint run ./...
vet:
	go vet ./...
sec:
	gosec -quiet ./...
fmt:
	gofmt -s -w .
clean:
	rm -rf bin dist tests/e2e/bin
