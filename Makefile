.PHONY: build test lint vet sec fmt clean
build:
	go build -trimpath -ldflags="-s -w" -o bin/osm ./cmd/osm
test:
	go test -race -count=1 ./...
lint:
	golangci-lint run ./...
vet:
	go vet ./...
sec:
	gosec -quiet ./...
fmt:
	gofmt -s -w .
clean:
	rm -rf bin dist
