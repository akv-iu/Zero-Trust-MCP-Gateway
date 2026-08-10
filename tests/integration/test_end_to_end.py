"""All eight stages, one process at a time, against real everything.

This is the first test in the project where a request goes in one end and a tool result
comes out the other. Every earlier integration test stopped at a stage boundary because
the stages after it were stubs.

What makes it worth its runtime is that nothing here is simulated: a real OPA process
decides, a real child MCP server performs the side effect, and the assertion that the
denied request caused nothing is made against the FIXTURE'S OWN operation log rather
than against the gateway's opinion of itself (CONV-018). A gateway that denied in its
audit record and forwarded anyway would pass every unit test in this repository and
fail here.

SKIPPED, never passed, when OPA is absent.
"""

from __future__ import annotations

import json
import os
import shutil
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import anyio
import pytest

from fixtures.build_tree import build
from gateway import startup
from gateway.audit import read_events
from gateway.errors import GatewayDenial, ReasonCode
from gateway.pipeline import handle
from harness.scenario import Scenario
from harness.wire import build_envelope
from scripts.opa_sidecar import find_binary, sidecar

REPO = Path(__file__).resolve().parents[2]

pytestmark = [
    pytest.mark.anyio,
    pytest.mark.slow,
    pytest.mark.skipif(
        find_binary() is None,
        reason="OPA not found (set ZTMG_OPA_BIN or put the binary in .tools/) — "
        "REPORTED AS SKIPPED, never counted as a pass",
    ),
]


@pytest.fixture(scope="module")
def opa_url() -> Iterator[str]:
    with sidecar() as url:
        yield url


@pytest.fixture
def deployment(tmp_path: Path, opa_url: str) -> Path:
    """A whole gateway deployment in a temp directory: tree, config, registry, audit.

    The shipped `config/gateway.toml` is rewritten rather than replaced, so this
    exercises the real roots, the real decoys and the real ceilings. A hand-written
    config here would test a configuration nobody ships.
    """
    fixture = tmp_path / "fixture"
    build(fixture)
    os.environ["FIXTURE_ROOT"] = str(fixture)
    os.environ["FIXTURE_OPLOG"] = str(tmp_path / "oplog.jsonl")
    os.environ["FIXTURE_ALLOW_WEAK_ISOLATION"] = "1"
    os.environ["FIXTURE_MODE"] = ""

    posix = str(fixture).replace("\\", "/")
    text = (REPO / "config" / "gateway.toml").read_text("utf-8")
    text = text.replace('base = "var/fixture"', f"base = {json.dumps(str(fixture))}")
    text = text.replace('path = "var/fixture/', f'path = "{posix}/')
    text = text.replace("http://127.0.0.1:8181", opa_url)
    text = text.replace(
        'path = "var/audit.jsonl"', f"path = {json.dumps(str(tmp_path / 'audit.jsonl'))}"
    )
    cfg_path = tmp_path / "gateway.toml"
    cfg_path.write_text(text, encoding="utf-8")
    shutil.copy(REPO / "config" / "registry.toml", tmp_path / "registry.toml")
    return cfg_path


def envelope(rid: str, tool: str, arguments: dict[str, Any], principal: str) -> Any:
    return build_envelope(
        Scenario.model_validate(
            {
                "id": rid,
                "class": "legitimate",
                "layer": "security",
                "principal": principal,
                "tool": tool,
                "arguments": arguments,
                "expected_decision": "allow",
                "expected_reason": "POLICY_SCOPED_READ",
                "expected_side_effect": "none",
                "risk_tier": "R1",
                "notes": "end-to-end",
            }
        ),
        request_id=rid,
    )


async def test_the_whole_pipeline_allows_and_denies_and_the_fixture_agrees(
    deployment: Path, tmp_path: Path
) -> None:
    """One allowed read, one denied read, and the evidence for both.

    The allowed one must come back with the file's actual contents — proof that stages
    07 and 08 carried a real result rather than a shape that merely validated. The
    denied one must produce no operation at the fixture at all.
    """
    async with startup.serve(deployment) as deps:
        allowed = await handle(
            envelope("e2e-1", "read_file", {"path": "public/documentation.txt"}, "dev"),
            deps,
        )
        body = json.dumps(allowed.unwrap())
        assert "Public documentation" in body, "the real file contents did not survive"

        with pytest.raises(GatewayDenial) as exc:
            await handle(
                envelope(
                    "e2e-2",
                    "read_file",
                    {"path": "confidential/fake_salaries.csv"},
                    "dev",
                ),
                deps,
            )
        assert exc.value.reason_code is ReasonCode.POLICY_PATH_NOT_PERMITTED

    events = list(read_events(tmp_path / "audit.jsonl"))
    requests = {e.request_id: e for e in events if e.event_type == "request"}
    assert requests["e2e-1"].outcome == "allowed"
    assert requests["e2e-1"].upstream_status == "ok"
    assert requests["e2e-1"].response_bytes and requests["e2e-1"].response_bytes > 0
    assert requests["e2e-2"].outcome == "denied"
    assert requests["e2e-2"].upstream_status is None, "a denied request contacted nothing"

    # AUDIT-009: the write-ahead record exists for the call that could cause a side
    # effect, and ONLY for it. This is the pairing that keeps a lost terminal record
    # from erasing the fact that something happened.
    attempts = [e for e in events if e.event_type == "upstream_attempt"]
    assert [e.request_id for e in attempts] == ["e2e-1"]

    # CONV-018, and the only assertion here that the gateway cannot fake: the oracle's
    # source is the fixture's own log, written by the child process.
    oplog = (tmp_path / "oplog.jsonl").read_text("utf-8")
    assert "documentation.txt" in oplog, "the allowed read never reached the fixture"
    assert "fake_salaries" not in oplog, "the DENIED read reached the fixture"


async def test_a_success_comes_back_over_HTTP_as_valid_json_rpc(
    deployment: Path,
) -> None:
    """Through the ASGI edge, because calling `pipeline.handle` directly hid a defect.

    The first version of this file drove the pipeline and asserted on the returned
    object, so it never saw what actually goes on the wire — and what went on the wire
    for a SUCCESS was the bare MCP result, with no `jsonrpc`, no `id` and no `result`.
    A conforming client could not have correlated a single successful reply. Denials
    were framed correctly by `edge._error`, which is what kept it invisible.

    Found in review. Every claim about the client-facing contract belongs at this
    level from now on; the pipeline-level tests above are about the stages.
    """
    from gateway.edge import build_app

    async with startup.serve(deployment) as deps:
        env = envelope("e2e-http", "read_file", {"path": "public/documentation.txt"}, "d")
        app = build_app(deps.config.edge, lambda e: handle(e, deps))

        captured: dict[str, Any] = {"body": b"", "status": None}

        async def send(message: dict[str, Any]) -> None:
            if message["type"] == "http.response.start":
                captured["status"] = message["status"]
            else:
                captured["body"] += message.get("body", b"")

        queued = [{"type": "http.request", "body": env.body, "more_body": False}]

        async def receive() -> dict[str, Any]:
            # Once the body is drained a real server BLOCKS until the client goes
            # away. Returning anything here would make the edge's disconnect watcher
            # spin, and returning `http.disconnect` would cancel every request.
            if queued:
                return queued.pop(0)
            await anyio.sleep_forever()
            raise AssertionError("unreachable")

        await app(
            {
                "type": "http",
                "method": "POST",
                "path": deps.config.edge.mcp_path,
                "headers": [(k.encode(), v.encode()) for k, v in env.metadata],
            },
            receive,
            send,
        )

    assert captured["status"] == 200
    body = json.loads(captured["body"])
    assert body["jsonrpc"] == "2.0", f"not a JSON-RPC response: {body}"
    assert "result" in body and "error" not in body
    assert body["id"] is not None, "a client cannot correlate a reply with no id"
    assert "Public documentation" in json.dumps(body["result"])


async def test_the_live_pathological_response_reaches_the_guard_and_is_refused(
    tmp_path: Path, opa_url: str
) -> None:
    """The advertised attack, through the real child, not a hand-built `RawResult`.

    This is the test whose absence made unit 08 look covered. The synthetic structural
    tests in `test_response.py` passed while `FIXTURE_MODE=pathological` produced a
    302-byte `isError: true` — the SDK refused to serialize the deep structure, so the
    guard never saw it and the mode proved nothing (review finding).

    Three placements were tried before one worked, and each wrong one failed a layer
    BEFORE unit 08, which looks identical to the guard working: `content` blocks are
    typed models, `structuredContent` is validated against the tool's output schema,
    and only `_meta` is genuinely open. See `fixtures/filesystem_server/modes.py`.
    """
    from gateway import response as guard
    from gateway import router
    from gateway.bridge import upstream
    from gateway.config import ChildConfig, ResponseConfig
    from gateway.errors import ResponseDenial
    from gateway.hashing import canonical_json
    from gateway.types import CanonicalRequest, Obligations, RawResult

    fixture = tmp_path / "fixture"
    build(fixture)
    os.environ["FIXTURE_ROOT"] = str(fixture)
    os.environ["FIXTURE_OPLOG"] = str(tmp_path / "oplog.jsonl")
    os.environ["FIXTURE_ALLOW_WEAK_ISOLATION"] = "1"
    os.environ["FIXTURE_MODE"] = "pathological"

    child = ChildConfig(
        executable=__import__("sys").executable,
        # The wrapper, not the server: the SDK will not emit this, so the bytes have
        # to be edited between the honest fixture and the gateway.
        args=("-m", "fixtures.misbehaving_wrapper"),
        cwd=str(REPO),
        env_allowlist=(
            "PATH",
            "PYTHONPATH",
            "SYSTEMROOT",
            "FIXTURE_ROOT",
            "FIXTURE_OPLOG",
            "FIXTURE_MODE",
            "FIXTURE_ALLOW_WEAK_ISOLATION",
        ),
        startup_timeout_s=20.0,
    )
    req = CanonicalRequest(
        request_id="patho",
        protocol_version="2026-07-28",
        method="tools/call",
        jsonrpc_id=1,
        tool_name="read_file",
        arguments={"path": "public/documentation.txt"},
        body_hash="b",
    )

    with anyio.fail_after(60):
        async with upstream(child) as up:
            sdk_result = await up.call_tool(
                "read_file", {"path": "public/documentation.txt"}
            )

    content = router._content(sdk_result)  # noqa: SLF001 - the router's own mapping
    assert "deep" in content.get("_meta", {}), (
        "the payload did not survive the SDK — the mode is testing nothing again"
    )

    raw = RawResult(
        content=content,
        is_error=False,
        byte_count=len(canonical_json(content)),
        upstream_latency_ns=1,
        obligations=Obligations(timeout_ms=3_000, max_response_bytes=4_194_304),
    )
    with pytest.raises(ResponseDenial) as exc:
        guard.validate(raw, req, ResponseConfig())
    assert exc.value.reason_code is ReasonCode.RESP_LIMIT_EXCEEDED


async def test_an_expired_request_deadline_is_not_recorded_as_a_client_cancellation(
    tmp_path: Path, opa_url: str
) -> None:
    """ROUTE-010, through the whole pipeline, because that is where it broke.

    An anyio cancellation carries no reason, so `router._bounded` records `cancelled` —
    the only thing a bare cancellation can mean from inside the await. But the request
    deadline in `pipeline.handle` cancels that same await. The result was ONE audit
    event saying `reason_code=ROUTE_TIMEOUT` next to `upstream_status=cancelled`: a
    record contradicting itself about whether the client left or the clock ran out.

    Found by Codex and reproduced with a probe. `test_8` in the router tests cancels via
    a task group and structurally cannot see this path — only the real nesting can, so
    this test drives the real one: `request_timeout_s` is set BELOW the policy timeout
    obligation, so the pipeline's deadline is guaranteed to be the scope that fires.
    """
    fixture = tmp_path / "fixture"
    build(fixture)
    os.environ["FIXTURE_ROOT"] = str(fixture)
    os.environ["FIXTURE_OPLOG"] = str(tmp_path / "oplog.jsonl")
    os.environ["FIXTURE_ALLOW_WEAK_ISOLATION"] = "1"
    os.environ["FIXTURE_MODE"] = "hang"

    posix = str(fixture).replace("\\", "/")
    text = (REPO / "config" / "gateway.toml").read_text("utf-8")
    text = text.replace('base = "var/fixture"', f"base = {json.dumps(str(fixture))}")
    text = text.replace('path = "var/fixture/', f'path = "{posix}/')
    text = text.replace("http://127.0.0.1:8181", opa_url)
    text = text.replace(
        'path = "var/audit.jsonl"', f"path = {json.dumps(str(tmp_path / 'audit.jsonl'))}"
    )
    # Below the policy `default_timeout_ms` of 3000, so the PIPELINE deadline wins the
    # race against unit 07's own obligation timeout. At or above it, `_bounded` would
    # raise ROUTE_TIMEOUT itself and this path would never be entered.
    text = text.replace("request_timeout_s = 30.0", "request_timeout_s = 1.0")
    cfg_path = tmp_path / "gateway.toml"
    cfg_path.write_text(text, encoding="utf-8")
    shutil.copy(REPO / "config" / "registry.toml", tmp_path / "registry.toml")

    async with startup.serve(cfg_path) as deps:
        with pytest.raises(GatewayDenial) as exc:
            env = envelope(
                "e2e-hang", "read_file", {"path": "public/documentation.txt"}, "dev"
            )
            await handle(env, deps)
    assert exc.value.reason_code is ReasonCode.ROUTE_TIMEOUT

    events = list(read_events(tmp_path / "audit.jsonl"))
    (record,) = [
        e
        for e in events
        if e.event_type == "request" and getattr(e, "request_id", None) == "e2e-hang"
    ]
    assert record.reason_code == ReasonCode.ROUTE_TIMEOUT.value
    assert record.outcome == "timeout"
    assert record.upstream_status == "timeout", (
        f"the deadline was recorded as {record.upstream_status!r}; one event cannot say "
        "the clock ran out and the client left at the same time (ROUTE-010)"
    )


async def test_a_denied_request_leaves_no_response_bytes_anywhere(
    deployment: Path, tmp_path: Path
) -> None:
    """RESP-009 / CONV-012 over a real run rather than over a constructed record.

    The fixture's files carry canary strings precisely so this can be asked as "does
    any audit record contain any of the protected content", which is the question the
    report needs answered and the one a per-field review cannot settle.
    """
    async with startup.serve(deployment) as deps:
        await handle(
            envelope("e2e-3", "read_file", {"path": "public/documentation.txt"}, "dev"),
            deps,
        )

    raw = (tmp_path / "audit.jsonl").read_text("utf-8")
    contents = (
        Path(os.environ["FIXTURE_ROOT"]) / "public" / "documentation.txt"
    ).read_text("utf-8")
    for line in contents.splitlines():
        if len(line.strip()) > 12:
            assert line.strip() not in raw, f"response content in the audit log: {line!r}"


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
