# Integration test image for `osm run`. Hermetic: ships only the osm
# binary, the mockupstream binary, and curl. No node, no claude-code, no
# external creds required — distinct from the e2e image.

FROM golang:1.26.3-bookworm@sha256:386d475a660466863d9f8c766fec64d7fdad3edac2c6a05020c09534d71edb4b AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -o /out/osm ./cmd/osm \
 && CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
      go build -trimpath -o /out/mockupstream ./tests/internal/mockupstream/cmd

FROM debian:bookworm-slim@sha256:0104b334637a5f19aa9c983a91b54c89887c0984081f2068983107a6f6c21eeb
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/osm /usr/local/bin/osm
COPY --from=build /out/mockupstream /usr/local/bin/mockupstream
RUN chmod +x /usr/local/bin/osm /usr/local/bin/mockupstream

ENV HOME=/root
ENV OSM_KEY=integration-test-pass
WORKDIR /work
CMD ["sleep", "infinity"]
