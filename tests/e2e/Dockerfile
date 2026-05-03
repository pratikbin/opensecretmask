FROM oven/bun:latest@sha256:87416c977a612a204eb54ab9f3927023c2a3c971f4f345a01da08ea6262ae30e

USER root

RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq sudo \
 && rm -rf /var/lib/apt/lists/*

# claude-code refuses to run as root with --dangerously-skip-permissions, so
# the e2e suite uses a non-root user. /workspace is owned by the test user
# so claude-code can read/write files placed there by the test harness.
RUN useradd -m -s /bin/bash -u 1001 osmtest \
 && mkdir -p /workspace \
 && chown -R osmtest:osmtest /workspace

USER osmtest
ENV HOME=/home/osmtest
ENV PATH=/home/osmtest/.local/bin:$PATH
WORKDIR /workspace

RUN curl -fsSL https://claude.ai/install.sh | bash \
 && claude --version

USER root
COPY bin/osm-linux-amd64 /usr/local/bin/osm
RUN chmod +x /usr/local/bin/osm \
 && osm --help >/dev/null

COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

USER osmtest
ENV HOME=/home/osmtest
WORKDIR /workspace

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["sleep", "infinity"]
