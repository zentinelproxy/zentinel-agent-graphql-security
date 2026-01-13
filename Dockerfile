# syntax=docker/dockerfile:1.4

# Sentinel GraphQL Security Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY sentinel-agent-graphql-security /sentinel-agent-graphql-security

LABEL org.opencontainers.image.title="Sentinel GraphQL Security Agent" \
      org.opencontainers.image.description="Sentinel GraphQL Security Agent for Sentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/raskell-io/sentinel-agent-graphql-security"

ENV RUST_LOG=info,sentinel_agent_graphql_security=debug \
    SOCKET_PATH=/var/run/sentinel/graphql-security.sock

USER nonroot:nonroot

ENTRYPOINT ["/sentinel-agent-graphql-security"]
