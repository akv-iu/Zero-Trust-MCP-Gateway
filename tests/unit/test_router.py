"""Acceptance tests for unit 07, the only stage that can cause a side effect."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, Any, cast

import anyio
import pytest

from fixtures.build_tree import build
from gateway import hashing, response, router
from gateway.audit import AuditBuilder
from gateway.config import ResponseConfig, RouterConfig
from gateway.context import current_audit
from gateway.errors import AuditFailure, ReasonCode, ResponseDenial, RouteDenial, Stage
from gateway.types import (
    AuthzContext,
    CanonicalRequest,
    Decision,
    DerivedAttributes,
    Obligations,
)
from harness.clients import protected, write_configs
from harness.oracle import Oracle
from harness.runner import Verdict, run_corpus
from harness.scenario import load
from scripts.opa_sidecar import find_binary, sidecar

if TYPE_CHECKING:
    from gateway.pipeline import Deps

REPO = Path(__file__).resolve().parents[2]


class AuditProbe:
    def __init__(self) -> None:
        self.fields: dict[str, Any] = {}

    def set(self, **values: Any) -> None:
        self.fields.update(values)


@pytest.fixture
def audit_probe() -> Any:
    probe = AuditProbe()
    token = current_audit.set(probe)
    try:
        yield probe
    finally:
        current_audit.reset(token)


def request(
    *,
    request_id: str = "route-1",
    method: str = "tools/call",
    tool: str | None = "read_file",
    arguments: dict[str, Any] | None = None,
) -> CanonicalRequest:
    return CanonicalRequest(
        request_id=request_id,
        protocol_version="2026-07-28",
        method=method,
        jsonrpc_id=1,
        tool_name=tool,
        arguments=(
            arguments if arguments is not None else {"path": "%70ublic/documentation.txt"}
        ),
        body_hash="body",
    )


def derived(req: CanonicalRequest) -> DerivedAttributes:
    canonical = "C:/fixture/public/documentation.txt" if req.tool_name else ""
    return DerivedAttributes(
        canonical_path=canonical,
        root="public" if req.tool_name else "",
        operation="read",
        classification="public",
        exists=True,
        arg_hash=hashing.argument_hash(req.arguments, canonical),
        raw_hash="raw",
        path_argument="path" if req.tool_name else "",
        relative_path="public/documentation.txt" if req.tool_name else "",
    )


def decision(
    req: CanonicalRequest,
    drv: DerivedAttributes,
    *,
    request_id: str | None = None,
    method: str | None = None,
    tool: str | None = None,
    timeout_ms: int = 1_000,
    max_response_bytes: int = 1_048_576,
) -> Decision:
    return Decision(
        request_id=request_id or req.request_id,
        method=method or req.method,
        tool_name=req.tool_name if tool is None else tool,
        decision="allow",
        reason_code=ReasonCode.POLICY_SCOPED_READ.value,
        risk_tier="R1",
        policy_revision="policy-test",
        obligations=Obligations(
            timeout_ms=timeout_ms, max_response_bytes=max_response_bytes
        ),
        arg_hash=drv.arg_hash,
    )


def context() -> AuthzContext:
    return AuthzContext(
        principal="developer",
        client_id="router-tests",
        roles=("developer",),
        auth_method="local_config",
        assurance="unverified_local",
        transport="streamable_http",
        environment="development",
    )


class Upstream:
    def __init__(self, result: Any | None = None) -> None:
        self.result: Any = (
            result if result is not None else {"content": cast("list[Any]", [])}
        )
        self.calls: list[tuple[str, dict[str, Any]]] = []

    async def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
        self.calls.append((tool, arguments))
        return self.result


@pytest.mark.slow
@pytest.mark.skipif(
    find_binary() is None,
    reason="OPA unavailable - the full mediation acceptance test cannot run",
)
def test_1_denied_corpus_rows_leave_no_effect_at_the_fixture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The mediation proof is the fixture observation, never the denial message."""
    root = tmp_path / "fixture"
    build(root)
    monkeypatch.setenv("FIXTURE_ROOT", str(root))
    monkeypatch.setenv("FIXTURE_OPLOG", str(tmp_path / "oplog.jsonl"))
    monkeypatch.setenv("FIXTURE_ALLOW_WEAK_ISOLATION", "1")
    monkeypatch.delenv("FIXTURE_MODE", raising=False)

    corpus = load()
    rows = tuple(
        s
        for s in corpus.malicious()
        if s.transport is None or s.transport.http_fate != "normalized"
    )
    principals = tuple(sorted({s.principal for s in rows}))
    with sidecar() as opa_url:
        configs = write_configs(
            principals,
            source=REPO / "config" / "gateway.toml",
            work=tmp_path,
            fixture_root=root,
            opa_url=opa_url,
        )
        with protected(configs) as client:
            report = run_corpus(rows, client, Oracle(root), root=root)

    bad = [r for r in report.results if r.verdict not in (Verdict.PASS, Verdict.SKIPPED)]
    assert report.prohibited_effects == 0, report.summary()
    assert not bad, [(r.scenario_id, r.verdict, r.detail) for r in bad]


def test_2_a_foreign_or_wrongly_bound_decision_cannot_open_the_gate() -> None:
    req = request()
    drv = derived(req)
    for dec in (
        decision(req, drv, request_id="some-other-request"),
        decision(req, drv, method="tools/list"),
        decision(req, drv, tool="delete_file"),
    ):
        with pytest.raises(RouteDenial) as caught:
            router._gate(req, drv, dec)  # pyright: ignore[reportPrivateUsage]
        assert caught.value.reason_code is ReasonCode.ROUTE_NO_DECISION


@pytest.mark.parametrize(
    "bad_decision", [True, object(), None], ids=["truthy", "object", "missing"]
)
def test_2b_an_unvalidated_value_is_a_controlled_no_decision(
    bad_decision: object,
) -> None:
    """ROUTE-001 names runtime values as well as the static type signature."""
    req = request()
    drv = derived(req)
    with pytest.raises(RouteDenial) as caught:
        router._gate(  # pyright: ignore[reportPrivateUsage]
            req, drv, cast("Decision", bad_decision)
        )
    assert caught.value.reason_code is ReasonCode.ROUTE_NO_DECISION


def test_2c_a_typed_deny_decision_cannot_open_the_gate() -> None:
    req = request()
    drv = derived(req)
    denied = decision(req, drv).model_copy(
        update={"decision": "deny", "reason_code": "POLICY_DEFAULT_DENY"}
    )
    with pytest.raises(RouteDenial) as caught:
        router._gate(req, drv, denied)  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason_code is ReasonCode.ROUTE_NO_DECISION


def test_3_arguments_changed_after_policy_are_refused() -> None:
    original = request()
    drv = derived(original)
    dec = decision(original, drv)
    changed = original.model_copy(
        update={"arguments": {"path": "confidential/fake_salaries.csv"}}
    )

    with pytest.raises(RouteDenial) as caught:
        router._gate(changed, drv, dec)  # pyright: ignore[reportPrivateUsage]
    assert caught.value.reason_code is ReasonCode.ROUTE_AUTHORIZATION_DIVERGENCE


@pytest.mark.anyio
@pytest.mark.parametrize(("requested", "ceiling"), [(25, 100), (500, 40)])
async def test_4_the_effective_timeout_is_enforced_and_audited(
    requested: int, ceiling: int, audit_probe: AuditProbe
) -> None:
    req = request()
    drv = derived(req)
    dec = decision(req, drv, timeout_ms=requested)
    ob = router._enforce(  # pyright: ignore[reportPrivateUsage]
        dec, RouterConfig(max_timeout_ms=ceiling)
    )
    calls = 0

    async def hangs() -> None:
        nonlocal calls
        calls += 1
        await anyio.sleep_forever()

    with anyio.fail_after(1):
        with pytest.raises(RouteDenial) as caught:
            await router._bounded(  # pyright: ignore[reportPrivateUsage]
                hangs(), ob
            )

    assert caught.value.reason_code is ReasonCode.ROUTE_TIMEOUT
    assert ob.timeout_ms == min(requested, ceiling)
    assert audit_probe.fields["obligations"] == ob.model_dump()
    assert audit_probe.fields["upstream_status"] == "timeout"
    assert calls == 1, "a timed-out protected operation must never be retried"


def test_5_the_sdk_limited_router_measures_and_unit_08_enforces_the_ceiling(
    audit_probe: AuditProbe,
) -> None:
    """The pinned SDK prevents a streaming abort; the documented fallback is real."""
    req = request(arguments={"path": "public/documentation.txt"})
    content = {"content": [{"type": "text", "text": "x" * 2_000}]}
    ob = Obligations(timeout_ms=1_000, max_response_bytes=100)

    raw = router._measure(  # pyright: ignore[reportPrivateUsage]
        content, False, 1, ob
    )

    assert raw.byte_count > ob.max_response_bytes
    assert audit_probe.fields["response_bytes"] == raw.byte_count
    with pytest.raises(ResponseDenial) as caught:
        response.validate(raw, req, ob, ResponseConfig())
    assert caught.value.reason_code is ReasonCode.RESP_TOO_LARGE


@pytest.mark.anyio
async def test_6_a_hanging_upstream_times_out_once_and_never_retries(
    audit_probe: AuditProbe,
) -> None:
    req = request()
    drv = derived(req)

    class Hanging(Upstream):
        async def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
            self.calls.append((tool, arguments))
            await anyio.sleep_forever()

    upstream = Hanging()
    dec = decision(req, drv, timeout_ms=25)
    with anyio.fail_after(1):
        with pytest.raises(RouteDenial) as caught:
            await router.forward(req, drv, dec, upstream, RouterConfig())

    assert caught.value.reason_code is ReasonCode.ROUTE_TIMEOUT
    assert len(upstream.calls) == 1
    assert audit_probe.fields["upstream_status"] == "timeout"


@pytest.mark.anyio
async def test_7_a_broken_upstream_is_controlled_and_not_retried(
    audit_probe: AuditProbe,
) -> None:
    req = request()
    drv = derived(req)

    class Broken(Upstream):
        async def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
            self.calls.append((tool, arguments))
            raise RouteDenial(ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE)

    upstream = Broken()
    with pytest.raises(RouteDenial) as caught:
        await router.forward(req, drv, decision(req, drv), upstream, RouterConfig())

    assert caught.value.reason_code is ReasonCode.ROUTE_UPSTREAM_UNAVAILABLE
    assert len(upstream.calls) == 1
    assert audit_probe.fields["upstream_status"] == "unavailable"


@pytest.mark.anyio
async def test_8_cancellation_reaches_the_call_and_is_not_recorded_as_error(
    audit_probe: AuditProbe,
) -> None:
    req = request()
    drv = derived(req)
    started = anyio.Event()
    cancelled = anyio.Event()

    class Cancellable(Upstream):
        async def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
            self.calls.append((tool, arguments))
            started.set()
            try:
                await anyio.sleep_forever()
            except anyio.get_cancelled_exc_class():
                cancelled.set()
                raise

    async with anyio.create_task_group() as tg:
        tg.start_soon(
            router.forward,
            req,
            drv,
            decision(req, drv),
            Cancellable(),
            RouterConfig(),
        )
        await started.wait()
        tg.cancel_scope.cancel()

    assert cancelled.is_set(), "the in-flight upstream await did not receive cancellation"
    assert audit_probe.fields["upstream_status"] == "cancelled"


@pytest.mark.anyio
async def test_9_tool_errors_and_partial_failures_are_never_router_successes(
    audit_probe: AuditProbe,
) -> None:
    class ToolError:
        is_error = True

        def model_dump(self, **_: Any) -> dict[str, Any]:
            return {"content": [{"type": "text", "text": "operation failed"}]}

    req = request()
    drv = derived(req)
    raw = await router.forward(
        req, drv, decision(req, drv), Upstream(ToolError()), RouterConfig()
    )

    assert raw.is_error is True
    assert audit_probe.fields["upstream_status"] == "tool_error"


@pytest.mark.anyio
async def test_write_ahead_record_precedes_the_only_upstream_call(
    audit_probe: AuditProbe,
) -> None:
    order: list[str] = []
    req = request()
    drv = derived(req)
    dec = decision(req, drv)

    class Sink:
        async def write(self, event: Any) -> None:
            assert event.request_id == req.request_id
            order.append("audit")

    class Ordered(Upstream):
        async def call_tool(self, tool: str, arguments: dict[str, Any]) -> Any:
            order.append("upstream")
            return await super().call_tool(tool, arguments)

    deps = SimpleNamespace(
        config=SimpleNamespace(router=RouterConfig()),
        audit=Sink(),
        registry=SimpleNamespace(server=SimpleNamespace(id="filesystem-fixture")),
        upstream=Ordered(),
    )
    await router.route(req, context(), drv, dec, cast("Deps", deps))
    assert order == ["audit", "upstream"]
    assert deps.upstream.calls == [("read_file", {"path": "public/documentation.txt"})], (
        "the canonical path, and no client credential field, must be forwarded"
    )


@pytest.mark.anyio
async def test_an_unwritable_attempt_record_prevents_upstream_contact(
    audit_probe: AuditProbe,
) -> None:
    req = request()
    drv = derived(req)
    upstream = Upstream()

    class BrokenSink:
        async def write(self, event: Any) -> None:
            raise AuditFailure(ReasonCode.AUDIT_WRITE_FAILED)

    deps = SimpleNamespace(
        config=SimpleNamespace(router=RouterConfig()),
        audit=BrokenSink(),
        registry=SimpleNamespace(server=SimpleNamespace(id="filesystem-fixture")),
        upstream=upstream,
    )
    with pytest.raises(AuditFailure):
        await router.route(req, context(), drv, decision(req, drv), cast("Deps", deps))
    assert upstream.calls == []


@pytest.mark.anyio
async def test_11_upstream_and_route_latency_are_separate_and_consistent() -> None:
    req = request()
    drv = derived(req)
    builder = AuditBuilder(req.request_id)
    token = current_audit.set(builder)
    try:
        with builder.stage(Stage.ROUTE):
            raw = await router.forward(
                req, drv, decision(req, drv), Upstream(), RouterConfig()
            )
        builder.set_outcome("allowed")
        event = builder.finalize()
    finally:
        current_audit.reset(token)

    upstream_ms = raw.upstream_latency_ns / 1_000_000
    assert event.upstream_latency_ms is not None
    assert abs(event.upstream_latency_ms - upstream_ms) < 1e-9
    assert event.stage_latency_ms["route"] >= upstream_ms
    assert event.total_latency_ms is not None
    assert event.total_latency_ms >= event.stage_latency_ms["route"]


@pytest.mark.anyio
async def test_plan_tools_list_is_filtered_by_policy(
    monkeypatch: pytest.MonkeyPatch, audit_probe: AuditProbe
) -> None:
    req = request(method="tools/list", tool=None, arguments={})
    drv = derived(req)
    dec = decision(req, drv)

    tools = {
        "read_file": SimpleNamespace(name="read_file", operation="read"),
        "delete_file": SimpleNamespace(name="delete_file", operation="delete"),
    }

    class Registry:
        server = SimpleNamespace(id="filesystem-fixture")

        def __init__(self) -> None:
            self.tools = tools

        def visible_tools(self, ctx: Any, predicate: Any) -> list[Any]:
            return [tool for tool in self.tools.values() if predicate(ctx, tool)]

    class Listing(Upstream):
        async def list_tools(self) -> dict[str, Any]:
            return {
                "tools": [
                    {"name": "read_file"},
                    {"name": "delete_file"},
                    {"name": "unregistered"},
                ]
            }

    async def discoverable(opa: Any, cfg: Any, ctx: Any, operation: str) -> bool:
        return operation == "read"

    monkeypatch.setattr(router.policy, "discoverable", discoverable)
    deps = SimpleNamespace(
        config=SimpleNamespace(router=RouterConfig(), policy=SimpleNamespace()),
        audit=object(),
        registry=Registry(),
        upstream=Listing(),
        opa=object(),
    )

    # `_discover` is the tools/list leg; route's write-ahead ordering is tested above.
    ob = router._enforce(  # pyright: ignore[reportPrivateUsage]
        dec, RouterConfig()
    )
    raw = await router._discover(  # pyright: ignore[reportPrivateUsage]
        req, context(), cast("Deps", deps), ob
    )
    assert [tool["name"] for tool in raw.content["tools"]] == ["read_file"]
