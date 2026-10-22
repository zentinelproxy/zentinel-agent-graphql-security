#!/usr/bin/env python3
"""Check that the agent's GraphQL answers replace the upstream's.

    python3 scripts/smoke-blocked-queries.py <smoke.py> <agent> <zentinel> <transport> <cases.json>

The shared harness (agent-smoke/smoke.py) decides "blocked" by whether the
upstream fixture saw the request. That does not work for request-body
decisions: Zentinel sends the request headers upstream before the buffered
body has been inspected, and when the agent then blocks, the upstream sees
the headers of a request whose body never comes. So this reuses the harness
to start the upstream, the agent and Zentinel, and checks the response
instead: each blocked query must be answered by the agent (a GraphQL
"errors" body with the expected code), never with the upstream's body.
"""

import argparse
import importlib.util
import json
import sys
import time


def main() -> int:
    smoke_py, agent, zentinel, transport, cases_file = sys.argv[1:6]
    spec = importlib.util.spec_from_file_location("agent_smoke", smoke_py)
    smoke = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(smoke)

    args = argparse.Namespace(
        agent=agent, zentinel=zentinel, name="graphql-security", type="custom",
        transport=transport, transport_args=None, agent_arg=[], agent_env=[],
        agent_config=None, events="request_headers,request_body", timeout_ms=2000,
        startup_timeout=60.0, socket_dir="/tmp", keep_work=False, report=None,
    )
    cases = json.load(open(cases_file))
    h = smoke.Harness(args)
    try:
        h.upstream = smoke.Upstream()
        h.start_agent()
        h.start_zentinel()
        probe = smoke.normalize_spec({"path": "/smoke"}, "probe", 200)
        deadline = time.monotonic() + args.startup_timeout
        while time.monotonic() < deadline and h.request(probe)[0] != 200:
            time.sleep(0.5)
        for case in cases:
            req = smoke.normalize_spec(dict(case, expect=200), case["name"])
            status, body = h.request(req)
            text = body.decode(errors="replace")
            if status != 200 or smoke.UPSTREAM_BODY.decode() in text:
                raise SystemExit(f"FAIL: {case['name']}: got {status} {text[:200]!r}, expected the agent's GraphQL error")
            try:
                errors = json.loads(text)["errors"]
            except (ValueError, KeyError, TypeError):
                raise SystemExit(f"FAIL: {case['name']}: not a GraphQL error response: {text[:200]!r}")
            codes = {e.get("extensions", {}).get("code") for e in errors}
            if case["code"] not in codes:
                raise SystemExit(f"FAIL: {case['name']}: error codes {sorted(map(str, codes))}, expected {case['code']}")
            print(f"ok   {case['name']}: answered by the agent with {case['code']}")
        print("PASS: blocked queries are answered by the agent")
        return 0
    except BaseException:
        h.dump_logs()
        raise
    finally:
        h.cleanup()


if __name__ == "__main__":
    sys.exit(main())
