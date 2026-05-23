.PHONY: build test lint vuln fix all clean

BIN := osm

build:
	go build -o $(BIN) ./cmd/osm

test:
	go test -race ./...

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
	go clean ./...
