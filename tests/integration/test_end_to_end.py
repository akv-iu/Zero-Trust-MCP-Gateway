"""HTTP client -> ASGI edge -> stdio child -> real fixture, over a real socket.

Review finding: unit 01 had no test proving the two halves connect. Both were
verified in isolation, which is exactly the gap that let the fixture's `**kwargs`
schema bug survive 35 passing fixture tests.

No policy is involved yet — the handler forwards straight to the upstream. Injecting
the handler keeps this honest: production wires `pipeline.handle` here, and there is
NO passthrough mode in the gateway that could be left switched on (CONV-001).
"""

from __future__ import annotations

import json
import socket
import sys
from pathlib import Path

import anyio
import httpx
import pytest

from fixtures.build_tree import build
from gateway import startup
from gateway.audit import AuditBuilder, AuditSink, read_events
from gateway.bridge import upstream
from gateway.config import EdgeConfig
from gateway.edge import build_app
from gateway.errors import Stage
from gateway.types import RawEnvelope, Untrusted

pytestmark = [pytest.mark.anyio, pytest.mark.slow]

REPO = Path(__file__).resolve().parents[2]


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture
def env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    build(tmp_path / "fixture")
    monkeypatch.setenv("FIXTURE_ROOT", str(tmp_path / "fixture"))
    monkeypatch.setenv("FIXTURE_OPLOG", str(tmp_path / "oplog.jsonl"))
    monkeypatch.setenv("FIXTURE_ALLOW_WEAK_ISOLATION", "1")
    monkeypatch.delenv("FIXTURE_MODE", raising=False)
    return tmp_path


async def test_http_request_reaches_the_real_fixture_and_is_audited(env: Path) -> None:
    """The whole chain, end to end, with the audit record joining it together."""
    import uvicorn

    port = free_port()
    sink = AuditSink(env / "audit.jsonl")
    sink.open()

    shipped, reg = startup.load_all(REPO / "config" / "gateway.toml")
    # Launch parameters come from the REGISTRY now (REG-002); `[child]` carries only
    # bridge tuning. Only the interpreter is substituted, because a bare `python`
    # need not be on PATH in every CI image.
    child = reg.server.child_config(shipped.child).model_copy(
        update={"executable": sys.executable, "cwd": str(REPO)}
    )

    with anyio.fail_after(90):
        async with upstream(child) as up:

            async def handler(envelope: RawEnvelope) -> Untrusted[dict]:
                builder = AuditBuilder(envelope.request_id)
                try:
                    body = json.loads(envelope.body)
                    with builder.stage(Stage.PROTOCOL):
                        method = body["method"]
                        params = body.get("params", {})
                    builder.set(mcp_method=method, tool_name=params.get("name"))
                    with builder.stage(Stage.ROUTE):
                        result = await up.call_tool(params["name"], params["arguments"])
                    builder.set(decision="allow", upstream_status="ok")
                    builder.set_outcome("allowed")
                    return Untrusted({"content": [c.text for c in result.content]})
                finally:
                    await builder.finalize_and_write(sink)

            cfg = EdgeConfig(host="127.0.0.1", port=port)
            server = uvicorn.Server(
                uvicorn.Config(
                    build_app(cfg, handler),
                    host=cfg.host,
                    port=port,
                    log_level="error",
                    access_log=False,
                )
            )
            async with anyio.create_task_group() as tg:
                tg.start_soon(server.serve)
                await _wait_ready(server)

                async with httpx.AsyncClient(timeout=30) as client:
                    resp = await client.post(
                        f"http://127.0.0.1:{port}/mcp",
                        headers={
                            "content-type": "application/json",
                            "mcp-protocol-version": "2026-07-28",
                            "mcp-method": "tools/call",
                            "mcp-name": "read_file",
                        },
                        json={
                            "jsonrpc": "2.0",
                            "id": 1,
                            "method": "tools/call",
                            "params": {
                                "name": "read_file",
                                "arguments": {"path": "public/documentation.txt"},
                            },
                        },
                    )
                server.should_exit = True

    # 1. the client got the file
    assert resp.status_code == 200, resp.text
    assert "Public documentation" in resp.json()["content"][0]

    # 2. the FIXTURE observed the read - the oracle's evidence, not the gateway's word
    oplog = (env / "oplog.jsonl").read_text("utf-8")
    assert "public/documentation.txt" in oplog

    # 3. exactly one audit event, correlated, with per-stage timings for the benchmark
    events = [e for e in read_events(sink.path) if e.event_type == "request"]
    assert len(events) == 1
    ev = events[0]
    assert ev.outcome == "allowed" and ev.tool_name == "read_file"
    assert {"protocol", "route"} <= set(ev.stage_latency_ms)
    assert ev.transport == "streamable_http"


async def test_edge_rejects_before_the_child_is_touched(env: Path) -> None:
    """A request denied at the edge must leave NO trace at the fixture.

    This is the mediation property in miniature, verified where it counts: at the
    protected system, not in the gateway's own response.
    """
    import uvicorn

    port = free_port()
    shipped, reg = startup.load_all(REPO / "config" / "gateway.toml")
    # Launch parameters come from the REGISTRY now (REG-002); `[child]` carries only
    # bridge tuning. Only the interpreter is substituted, because a bare `python`
    # need not be on PATH in every CI image.
    child = reg.server.child_config(shipped.child).model_copy(
        update={"executable": sys.executable, "cwd": str(REPO)}
    )

    with anyio.fail_after(90):
        async with upstream(child) as up:
            reached = False

            async def handler(envelope: RawEnvelope) -> Untrusted[dict]:
                nonlocal reached
                reached = True
                await up.call_tool("read_file", {"path": "public/documentation.txt"})
                return Untrusted({})

            cfg = EdgeConfig(
                host="127.0.0.1", port=port, allowed_origins=("http://localhost:3000",)
            )
            server = uvicorn.Server(
                uvicorn.Config(
                    build_app(cfg, handler),
                    host=cfg.host,
                    port=port,
                    log_level="error",
                    access_log=False,
                )
            )
            async with anyio.create_task_group() as tg:
                tg.start_soon(server.serve)
                await _wait_ready(server)
                async with httpx.AsyncClient(timeout=30) as client:
                    bad_origin = await client.post(
                        f"http://127.0.0.1:{port}/mcp",
                        headers={"origin": "http://evil.test"},
                        json={},
                    )
                    wrong_path = await client.post(
                        f"http://127.0.0.1:{port}/nope", json={}
                    )
                    removed_method = await client.get(f"http://127.0.0.1:{port}/mcp")
                server.should_exit = True

    assert bad_origin.status_code == 403
    assert wrong_path.status_code == 404
    assert removed_method.status_code == 405
    assert not reached, "a rejected request reached the handler"
    assert not (env / "oplog.jsonl").exists(), "the fixture saw a rejected request"


async def _wait_ready(server: object, timeout: float = 20.0) -> None:
    with anyio.fail_after(timeout):
        while not getattr(server, "started", False):
            await anyio.sleep(0.05)
