#!/usr/bin/env bash
# Smoke test: run the agent binary behind a real Zentinel (fail-closed) with
# the shared harness from zentinelproxy/.github (agent-smoke/smoke.py).
#
#   AGENT_SMOKE=<path to smoke.py> scripts/smoke-test.sh [<agent-binary> <zentinel-binary>]
#
# The binaries default to $AGENT_BIN and $ZENTINEL_BIN, which the shared
# release workflow sets. Run by that workflow on every platform before any
# asset is published, and by CI on every push and pull request.
#
# With no config file (the defaults: depth 10, 10 aliases, batches of 5,
# introspection denied), over the Unix socket and over gRPC, with the agent
# subscribed to request headers and bodies:
#   1. the harness: shallow queries are forwarded to the upstream (200), and
#      with the agent stopped they are refused;
#   2. scripts/smoke-blocked-queries.py: a query 12 levels deep, an
#      introspection query, 12 aliases and a batch of 6 are answered by the
#      agent (200 with a GraphQL "errors" body carrying DEPTH_EXCEEDED,
#      INTROSPECTION_BLOCKED, TOO_MANY_ALIASES, TOO_MANY_BATCH_QUERIES), never
#      with the upstream's response. (The harness cannot check these by
#      upstream count: Zentinel sends the request headers upstream before the
#      body is inspected, so the upstream sees the start of a blocked request
#      whose body never arrives.) Zentinel up to 26.10_7 sends no request
#      body to agents without a `waf` block, so there this check is reported
#      as a known limitation instead of failing.

set -euo pipefail

AGENT_BIN=${1:-${AGENT_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
ZENTINEL_BIN=${2:-${ZENTINEL_BIN:?usage: smoke-test.sh <agent-binary> <zentinel-binary>}}
AGENT_SMOKE=${AGENT_SMOKE:?set AGENT_SMOKE to agent-smoke/smoke.py from zentinelproxy/.github}

abs() { echo "$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; }
AGENT_BIN=$(abs "$AGENT_BIN"); ZENTINEL_BIN=$(abs "$ZENTINEL_BIN"); AGENT_SMOKE=$(abs "$AGENT_SMOKE")
BLOCKED=$(abs "$(dirname "$0")/smoke-blocked-queries.py")

# The agent reads config.yaml from its working directory if present; run it
# from an empty one so the defaults apply.
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$dir"

python3 - > cases.json <<'PY'
import json
def q(name, query, code=None):
    body = query if isinstance(query, str) else json.dumps(query)
    spec = {"name": name, "method": "POST", "path": "/graphql",
            "headers": {"Content-Type": "application/json"}, "body": body}
    if code:
        spec["code"] = code
    return spec
deep = "{ a { b { c { d { e { f { g { h { i { j { k { l } } } } } } } } } } } }"
aliases = "{ " + " ".join(f"a{i}: user {{ id }}" for i in range(12)) + " }"
blocked = [
    q("query 12 levels deep", {"query": deep}, "DEPTH_EXCEEDED"),
    q("introspection query", {"query": "{ __schema { types { name } } }"}, "INTROSPECTION_BLOCKED"),
    q("12 aliases", {"query": aliases}, "TOO_MANY_ALIASES"),
    q("batch of 6 queries", [{"query": f"{{ user{i} {{ id }} }}"} for i in range(6)], "TOO_MANY_BATCH_QUERIES"),
]
print(json.dumps(blocked))
open("clean.json", "w").write(json.dumps(q("shallow query", {"query": "{ user(id: 1) { name posts { title } } }"})))
open("allowed.json", "w").write(json.dumps([
    dict(q("query 5 levels deep", {"query": "{ a { b { c { d { e } } } } }"}), expect=200),
    dict(q("batch of 2 queries", [{"query": "{ a { id } }"}, {"query": "{ b { id } }"}]), expect=200),
]))
PY

# Zentinel releases up to 26.10_7 never send a request body to an agent
# unless the config has a `waf` block, so a body-inspecting agent sees only
# headers there. Against those (and only those) the blocked-query check is
# allowed to fail; against anything newer it must pass.
zentinel_release=$("$ZENTINEL_BIN" --version | sed -n 's/.*(release \([^,)]*\).*/\1/p')
known_no_bodies=0
case "$zentinel_release" in
    2[0-5].*|26.0[1-9]_*|26.10_[1-7]|26.10_0*) known_no_bodies=1 ;;
esac

for transport in uds grpc; do
    echo "=== graphql-security agent over $transport: allowed queries"
    python3 "$AGENT_SMOKE" --agent "$AGENT_BIN" --zentinel "$ZENTINEL_BIN" --name graphql-security \
        --transport "$transport" --events request_headers,request_body \
        --clean "$(cat clean.json)" --cases allowed.json
    echo "=== graphql-security agent over $transport: blocked queries"
    if ! python3 "$BLOCKED" "$AGENT_SMOKE" "$AGENT_BIN" "$ZENTINEL_BIN" "$transport" cases.json; then
        if [ "$known_no_bodies" = 1 ]; then
            echo "KNOWN: $zentinel_release sends request bodies to agents only when the config has a"
            echo "       waf block (fixed in zentinelproxy/zentinel after 26.10_7), so this agent cannot"
            echo "       block queries behind it. Not failing the smoke test for that release."
        else
            exit 1
        fi
    fi
done
