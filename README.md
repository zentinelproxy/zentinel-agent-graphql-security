<p align="center">
  <a href="https://zentinelproxy.io">
    <picture>
      <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-dark.svg">
      <img alt="Zentinel" src="https://raw.githubusercontent.com/zentinelproxy/design/main/marks/lockup/zentinel-lockup-light.svg" height="52">
    </picture>
  </a>
</p>

<h3 align="center">GraphQL security agent</h3>

<p align="center">Parses GraphQL request bodies and enforces limits on depth, cost, aliases, batch size and introspection, at the request-body stage.</p>

<p align="center">
  <a href="https://github.com/zentinelproxy/zentinel-agent-graphql-security/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/zentinelproxy/zentinel-agent-graphql-security/actions/workflows/ci.yml/badge.svg"></a>
  <img alt="License: Apache-2.0" src="https://img.shields.io/badge/license-Apache--2.0-9b4d8a?style=flat&labelColor=1f161e">
  <img alt="Agent protocol v2" src="https://img.shields.io/badge/agent%20protocol-v2-f68d31?style=flat&labelColor=1f161e">
</p>

<p align="center">
  <a href="https://registry.zentinelproxy.io/graphql-security/">Registry</a> &middot;
  <a href="https://docs.zentinelproxy.io">Docs</a> &middot;
  <a href="https://github.com/zentinelproxy">All repositories</a>
</p>

For teams running a GraphQL API behind Zentinel who want abusive queries stopped before they reach the resolver. The agent parses each query with [apollo-parser](https://crates.io/crates/apollo-parser) (no schema needed), runs the enabled analyzers, and on any violation answers HTTP 200 with a GraphQL `errors` body instead of forwarding the request. `settings.fail_action: allow` turns it into log-only mode. If the agent is unreachable, the `failure-mode` of the Zentinel filter decides.

## Quick start

```bash
zentinel bundle install graphql-security
zentinel-graphql-security-agent -s /tmp/zentinel-graphql-security.sock
```

Without a config file the agent runs with the defaults below (introspection blocked, depth 10, cost 1000).

```kdl
system {
    worker-threads 0
}

listeners {
    listener "http" {
        address "0.0.0.0:8080"
        protocol "http"
    }
}

upstreams {
    upstream "graphql-backend" {
        target "127.0.0.1:4000"
    }
}

// Request bodies reach agents only with body inspection switched on.
waf {
    mode "off"
    body-inspection {
        inspect-request-body #true
        max-inspection-bytes 1048576
        content-types "application/json"
    }
}

agents {
    agent "graphql-security" type="custom" {
        unix-socket "/tmp/zentinel-graphql-security.sock"
        events "request_headers" "request_body"
        request-body-mode "buffer"
        timeout-ms 200
    }
}

filters {
    filter "graphql-security" {
        type "agent"
        agent "graphql-security"
        failure-mode "closed"
    }
}

routes {
    route "graphql" {
        matches { path-prefix "/graphql" }
        upstream "graphql-backend"
        filters "graphql-security"
    }
}
```

```bash
curl -s -H 'content-type: application/json' \
  -d '{"query":"{ __schema { types { name } } }"}' http://localhost:8080/graphql
# {"errors":[{"message":"...","extensions":{"code":"INTROSPECTION_BLOCKED","zentinel":true}}]}
```

## Install

### Bundle (recommended)

```bash
zentinel bundle install graphql-security
```

Downloads the release binary pinned in Zentinel's bundle lock and installs it as `zentinel-graphql-security-agent`.

### Release binaries

Tarballs for `linux-x86_64`, `linux-aarch64` and `darwin-aarch64` are attached to each [release](https://github.com/zentinelproxy/zentinel-agent-graphql-security/releases).

### From source

```bash
cargo install --git https://github.com/zentinelproxy/zentinel-agent-graphql-security   # needs protoc
```

Installs `zentinel-graphql-security-agent`.

## Configuration

The agent reads a YAML file (`-c`, default `config.yaml`); if the file does not exist it starts with the defaults. It also accepts configuration over the protocol (`on_configure`), but Zentinel 0.6.50 does not forward an `agent { config { ... } }` block, so set it here.

| Option | Default | Meaning |
|---|---|---|
| `-c`, `--config` | `config.yaml` | Path to the YAML configuration file. |
| `-s`, `--socket` | `/tmp/zentinel-graphql-security.sock` | Unix socket to listen on. |
| `--grpc-address` | none | Listen for gRPC on this address instead of the socket, e.g. `0.0.0.0:50051`. |
| `-l`, `--log-level` | `info` | `trace`, `debug`, `info`, `warn` or `error`. `RUST_LOG` is not read. |

Configuration file keys. Every section is optional; unknown keys are ignored, so check spelling.

| Option | Default | Meaning |
|---|---|---|
| `settings.max_body_size` | `1048576` | Larger bodies are rejected with `INVALID_REQUEST`. |
| `settings.debug_headers` | `false` | Add `X-GraphQL-Depth`, `-Complexity`, `-Aliases`, `-Operations` and `-Fields` to the response. Zentinel 0.6.50 drops headers sent from the body phase, so these do not arrive. |
| `settings.fail_action` | `block` | `block` answers with the errors body; `allow` only logs violations. |
| `depth.enabled` | `true` | Enable depth limiting. |
| `depth.max_depth` | `10` | Maximum selection nesting, following fragments (cycles are cut). |
| `depth.ignore_introspection` | `true` | Do not count `__schema` / `__type` subtrees. |
| `complexity.enabled` | `true` | Enable cost analysis. |
| `complexity.max_complexity` | `1000` | Maximum estimated cost. |
| `complexity.default_field_cost` | `1` | Cost of a field without an override. |
| `complexity.default_list_multiplier` | `10` | Multiplier for a field's children when it has no list-size argument. |
| `complexity.list_size_arguments` | `first`, `last`, `limit`, `pageSize` | Arguments whose integer value is used as the multiplier. |
| `complexity.field_costs` | empty | Per-field cost, e.g. `Query.users: 10`. |
| `complexity.type_costs` | empty | Per-type cost, applied where the parent type is known (root fields, fragments, inline fragments). |
| `aliases.enabled` | `true` | Enable alias limiting. |
| `aliases.max_aliases` | `10` | Maximum aliases in one query. |
| `aliases.max_duplicate_aliases` | `3` | Maximum aliases of the same field. |
| `batch.enabled` | `true` | Enable batch limiting. |
| `batch.max_queries` | `5` | Maximum operations in a JSON-array batch. |
| `introspection.enabled` | `true` | Enable introspection control. |
| `introspection.allow` | `false` | Allow introspection for everyone. |
| `introspection.allow_typename` | `true` | Allow `__typename`. |
| `introspection.allowed_clients` | empty | Exact client IPs or header values allowed to introspect (no CIDR). Does not work yet, see below. |
| `introspection.allowed_clients_header` | none | Header whose value is compared with `allowed_clients`. |
| `field_auth.enabled` | `false` | Enable field rules. Not usable yet, see below. |
| `field_auth.rules[]` | empty | `fields` (glob patterns), `require_roles` / `require_scopes` (any of), `roles_header` / `scopes_header` (defaults `x-user-roles`, `x-user-scopes`). |
| `persisted_queries.enabled` | `false` | Enable the allowlist. |
| `persisted_queries.mode` | `allowlist` | `allowlist` permits only listed hashes; `cache` permits everything and does nothing else. |
| `persisted_queries.allowlist_file` | none | JSON file `{"queries":[{"hash":"<sha256 hex>","name":"..."}]}`, loaded at start. A missing file means an empty list. |
| `persisted_queries.require_hash` | `false` | Reject requests without `extensions.persistedQuery.sha256Hash`. |

The hash of a query is the SHA-256 of its text with surrounding whitespace trimmed (`printf '%s' '{ users { id } }' | shasum -a 256`), compared case-insensitively.

Full reference: <https://registry.zentinelproxy.io/graphql-security/>

## How it works

- **Body only.** The headers event is always answered with "allow, send the body"; analysis runs on the final body chunk. `GET` requests with the query in the URL are not inspected, and the proxy only sends bodies when `waf { body-inspection { inspect-request-body #true } }` is set and the content type matches. Use `request-body-mode "buffer"` and a `max-inspection-bytes` at least as large as `settings.max_body_size`: the agent analyzes only the last chunk it receives, and a body cut off at the inspection limit is allowed without analysis.
- **Analyzers:** depth, complexity, aliases, batch (JSON array of operations), introspection, field rules and persisted queries. Every operation in a batch is analyzed, and all violations are reported together.
- **Block response:** status 200 and `{"errors":[{"message", "extensions":{"code","zentinel":true, "actual", "max", "field"}}]}`. Codes: `DEPTH_EXCEEDED`, `COMPLEXITY_EXCEEDED`, `TOO_MANY_ALIASES`, `TOO_MANY_BATCH_QUERIES`, `INTROSPECTION_BLOCKED`, `FIELD_UNAUTHORIZED`, `QUERY_NOT_ALLOWED`, `PARSE_ERROR`, `INVALID_REQUEST` (not JSON, no `query`, or too large). The agent asks for `Content-Type: application/json` as a response-header operation, which Zentinel 0.6.50 does not apply to a block decided on the body.
- **Complexity** is an estimate without a schema: each field costs its configured cost, and the fields under it are multiplied by its list-size argument or `default_list_multiplier`. Multipliers apply one level down and do not compound.
- **Metrics** over the agent protocol: `graphql_security_requests_total`, `graphql_security_requests_blocked_total`, `graphql_security_block_rate_percent`.

Known limitations in the current code:

- **Field rules and introspection allowlists cannot see the request.** The body is analyzed with no headers and the client IP `unknown`, so `allowed_clients` never matches, and with `field_auth` enabled every field a rule matches is denied regardless of the caller's roles. Nested selector patterns such as `User.email` only match through fragments, because nested field types are unknown without a schema.
- **Persisted queries trust the client's hash.** In `allowlist` mode an `extensions.persistedQuery.sha256Hash` value is checked instead of the query's own hash, so a client can send any query with a listed hash. Hash-only (APQ) requests without a `query` are rejected as `INVALID_REQUEST`.

## Development

```bash
cargo build
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all --check
```

Needs stable Rust (CI uses `dtolnay/rust-toolchain@stable`) and `protoc` (CI installs `protobuf-compiler`).

## Related

- [Registry page](https://registry.zentinelproxy.io/graphql-security/)
- [Agent configuration](https://docs.zentinelproxy.io/configuration/agents/)
- [Agent protocol v2](https://docs.zentinelproxy.io/agents/v2/)
- [Zentinel](https://github.com/zentinelproxy/zentinel)

## License

Apache-2.0, see [`LICENSE`](LICENSE).

---

<p align="center">
  <sub>Part of <a href="https://zentinelproxy.io">Zentinel</a>, the security-first reverse proxy. The shisa guards the gate.</sub>
</p>
