.PHONY: build test lint vuln fix generate all clean

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

# generate regenerates the sqlc type-safe store/db package from the SQL files.
generate:
	go run github.com/sqlc-dev/sqlc/cmd/sqlc@latest generate

all: build test lint

clean:
	rm -f $(BIN)
	go clean ./...

