# syntax=docker/dockerfile:1.4

# Zentinel GraphQL Security Agent Container Image
#
# Targets:
#   - prebuilt: For CI with pre-built binaries

################################################################################
# Pre-built binary stage (for CI builds)
################################################################################
FROM gcr.io/distroless/cc-debian12:nonroot AS prebuilt

COPY zentinel-graphql-security-agent /zentinel-graphql-security-agent

LABEL org.opencontainers.image.title="Zentinel GraphQL Security Agent" \
      org.opencontainers.image.description="Zentinel GraphQL Security Agent for Zentinel reverse proxy" \
      org.opencontainers.image.vendor="Raskell" \
      org.opencontainers.image.source="https://github.com/zentinelproxy/zentinel-agent-graphql-security"

ENV RUST_LOG=info,zentinel_agent_graphql_security=debug \
    SOCKET_PATH=/var/run/zentinel/graphql-security.sock

USER nonroot:nonroot

ENTRYPOINT ["/zentinel-graphql-security-agent"]
