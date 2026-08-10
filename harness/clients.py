"""Execution modes. Two implementations of one protocol.

This is the one place in the project where a Protocol with two implementations is
justified: the same scenario body must run against either path, and the paired
benchmark alternates between them within a single run (HARN-014).

HARN-001: `direct` exists only to demonstrate the unsafe baseline against synthetic
fixtures. It MUST NOT be reachable from any protected client configuration, so its
constructor refuses unless the harness explicitly enables it.

WHY `call` TAKES A WHOLE SCENARIO. It used to take `(tool, arguments)`, which is
everything `direct` needs and two thirds of what `protected` needs. The missing third
is not a convenience:

  * **The principal.** `identity.resolve` deliberately never reads the request
    (IDENT-003, held by an AST test), so a principal cannot be carried on the wire at
    all. It comes from `[identity]` in the gateway's own config, which means running a
    scenario as `intern` requires a gateway configured as `intern`. `ProtectedClient`
    therefore holds ONE GATEWAY PER PRINCIPAL and dispatches on `scenario.principal`.
    Forty-nine of the corpus's rows are `intern` and fourteen are `developer`; running
    them all under one identity would score most of the policy matrix against the
    wrong grants and report it as a result.
  * **The wire damage.** A `layer = "protocol"` row IS its wire form — a header
    disagreeing with the body names two tools and cannot be expressed as one tool plus
    arguments. `harness.wire.build_envelope` needs the `transport` block.

Passing the scenario keeps both available without a parameter list that grows every
time the corpus learns a new axis.
"""

from __future__ import annotations

import json
import os
from collections.abc import AsyncGenerator, Generator, Mapping
from contextlib import AsyncExitStack, asynccontextmanager, contextmanager
from dataclasses import dataclass, replace
from functools import partial
from pathlib import Path
from typing import Any, Final, Protocol, cast, runtime_checkable

import anyio
from anyio.from_thread import BlockingPortal, start_blocking_portal

from fixtures.filesystem_server import tools
from gateway.edge import HANDLER_BACKSTOP
from harness.scenario import Scenario
from harness.wire import Response, build_envelope, free_port, post_raw

ALLOW_DIRECT_ENV = "ZTMG_ALLOW_DIRECT"

# -- client-side outcome codes ---------------------------------------------
#
# Four distinct ways a request can fail to become a gateway decision. They were ONE
# code — anything without a JSON body scored `TRANSPORT_REJECTED` — and a review
# proved that an empty HTTP 500 therefore satisfied the two rows that pass on a
# transport refusal: the gateway could crash and the corpus would report it as the
# HTTP parser doing its job. None of these is a `ReasonCode`: the gateway did not
# produce them, the client did, and blurring that line is how a harness starts
# grading its own answers.

TRANSPORT_REJECTED = "TRANSPORT_REJECTED"
"""4xx with no JSON-RPC body: the request never became a gateway request.

A CR inside a header value is refused by h11 before the gateway runs, so there is no
reason code and no audit event — the corpus records that as `Transport.http_fate =
"rejected"`. Reporting the scenario's own `expected_reason` here would make the row
assert what the client had just been told to say, which is the self-fulfilling shape
this project has been bitten by twice. `runner.score` compares this against the
DECLARED fate instead, and requires zero audit events alongside it."""

HTTP_FAILURE = "HTTP_FAILURE"
"""5xx: the gateway answered, at the HTTP layer, that it had broken.

Never a denial. Every denial this gateway makes is a reason-coded 4xx built by
`edge._error`; a 5xx means something escaped that path entirely."""

GATEWAY_RESPONSE_INVALID = "GATEWAY_RESPONSE_INVALID"
"""A body arrived and is not a conforming JSON-RPC 2.0 response.

This is a finding about the gateway, not a denial, and it must never be scored as
one. Missing `result`, `"jsonrpc": "1.0"`, no `id`, both `result` and `error`, or an
unrelated JSON error document from something that is not the gateway at all — all of
them used to be read as `allow` by a client that only asked whether `error` was
absent."""

NO_RESPONSE = "NO_RESPONSE"
"""No HTTP status line: the connection died, was refused, or timed out.

No scenario expects it, so it always scores FAIL — the correct verdict for "the
system under test stopped being under test"."""

CLIENT_CODES: Final = frozenset(
    {TRANSPORT_REJECTED, HTTP_FAILURE, GATEWAY_RESPONSE_INVALID, NO_RESPONSE}
)


@dataclass(frozen=True)
class AuditJoin:
    """The gateway's own record of this request, joined to it (HARN-009).

    Correlation is POSITIONAL — the audit events this one call appended — because the
    edge mints the `request_id` itself and a successful reply carries no trace of it.
    That is exact only while requests are strictly sequential, which `assert_serialised`
    already requires for the oracle's own byte-offset correlation, so the two share one
    precondition rather than adding a second.

    `count` is what makes an unjoinable scenario visible: HARN-009 says a decision that
    cannot be joined to an audit event is INDETERMINATE and never a pass.
    """

    count: int
    request_id: str | None = None
    reason_code: str | None = None
    outcome: str | None = None


@dataclass(frozen=True)
class CallOutcome:
    """What the client observed. Deliberately NOT evidence of a side effect."""

    decision: str  # "allow" | "deny" | "error"
    reason_code: str | None = None
    result: Any = None
    error: str | None = None
    audit: AuditJoin | None = None
    """None means this client has no audit source — `direct` mode authorizes nothing
    and writes nothing. The runner skips the join for those rather than reporting 66
    INDETERMINATE verdicts for a log that was never supposed to exist."""


@runtime_checkable
class Client(Protocol):
    mode: str

    def call(self, scenario: Scenario) -> CallOutcome: ...


class DirectClient:
    """Test driver straight to the fixture. No gateway, no policy, no protection.

    Every call reports `allow` because nothing is deciding anything. That is not a
    bug — scoring a malicious scenario against this client is what produces the
    unprotected baseline.
    """

    mode = "direct"

    def __init__(self) -> None:
        if os.environ.get(ALLOW_DIRECT_ENV) != "1":
            raise RuntimeError(
                f"direct mode requires {ALLOW_DIRECT_ENV}=1. It bypasses the gateway "
                "entirely and must never be reachable from a protected configuration."
            )

    def call(self, scenario: Scenario) -> CallOutcome:
        # `principal` is ignored on purpose: there is nothing here to authorize
        # against, and pretending otherwise would make the baseline look defended.
        try:
            return CallOutcome(
                decision="allow", result=tools.call(scenario.tool, scenario.arguments)
            )
        except Exception as e:  # noqa: BLE001 - the fixture's failure is data
            # NOTE: an upstream error is NOT a denial. Nothing authorised anything;
            # the operation was attempted and failed. The oracle still sees the attempt.
            return CallOutcome(decision="allow", error=f"{type(e).__name__}: {e}")


# ===========================================================================
# protected
# ===========================================================================


@dataclass(frozen=True)
class Endpoint:
    principal: str
    port: int
    mcp_path: str
    audit_path: Path
    response_timeout_s: float


class _AuditTail:
    """Audit events appended since the last read, for one gateway.

    Positional, and it holds no request ids of its own: the gateway mints those and a
    successful reply does not echo one back, so "the events this call produced" is the
    only join available without changing production code to serve the harness.

    Re-reads the whole file each time, which is O(n²) over a run and irrelevant at
    corpus scale — a few hundred short lines. `read_events` is strict by design
    (AUDIT-013: a corrupt line raises rather than being skipped), and that strictness
    is worth more here than the cost of a re-read.
    """

    def __init__(self, path: Path) -> None:
        self._path = path
        self._seen = 0

    def take(self) -> list[Any]:
        from gateway.audit import read_events

        events = list(read_events(self._path))
        new = events[self._seen :]
        self._seen = len(events)
        return new


class ProtectedClient:
    """Test driver -> HTTP -> gateway -> fixture. The system under test.

    Requests go over a REAL SOCKET to a real uvicorn, not into `pipeline.handle` and
    not into the ASGI callable directly. That is the whole point of the class and it
    is not a preference:

      * `pipeline.handle` returns the response object. Asserting on it is what let a
        success ship for weeks with no `jsonrpc`, no `id` and no `result` — every
        denial was framed correctly, so nothing looked wrong (unit 08 review).
      * Calling the ASGI app with hand-built header pairs skips the HTTP parser, and
        the HTTP parser is a scored participant: `Transport.http_fate` records that
        RFC 9110 strips edge OWS before the guard sees the value, and that h11 refuses
        a CR outright. Both are measured facts about our own stack. A corpus that
        bypassed the parser would report `normalized` rows as denials the gateway
        made, which it did not.

    One gateway per principal, all up at once, chosen per scenario — see the module
    docstring for why identity cannot ride on the request.
    """

    mode = "protected"

    def __init__(self, portal: BlockingPortal, endpoints: Mapping[str, Endpoint]) -> None:
        self._portal = portal
        self._endpoints = endpoints
        self._tails = {p: _AuditTail(e.audit_path) for p, e in endpoints.items()}

    @property
    def principals(self) -> tuple[str, ...]:
        return tuple(sorted(self._endpoints))

    def call(self, scenario: Scenario) -> CallOutcome:
        endpoint = self._endpoints.get(scenario.principal)
        if endpoint is None:
            # Loud, and not a denial: a corpus row naming a principal no gateway was
            # started for is a harness configuration error. Scoring it as `deny` would
            # let a typo in the corpus read as the gateway defending something.
            raise KeyError(
                f"{scenario.id}: no gateway configured for principal "
                f"{scenario.principal!r}; started: {self.principals}"
            )

        # Drained BEFORE the call, so anything left over from a previous row cannot be
        # attributed to this one. Positional correlation is only exact if the window
        # starts empty.
        tail = self._tails[scenario.principal]
        tail.take()

        env = build_envelope(scenario)
        response = self._portal.call(
            partial(
                post_raw,
                endpoint.port,
                endpoint.mcp_path,
                env.body,
                [(k, v) for k, v in env.metadata],
                timeout_s=endpoint.response_timeout_s,
            )
        )
        outcome = _outcome(response, _sent_jsonrpc_id(env.body))
        return replace(outcome, audit=_join(tail.take()))


def _outcome(response: Response, sent_id: Any) -> CallOutcome:
    """The gateway's reply, read as a CLAIM and validated before it is believed.

    An earlier version asked one question — "is there an `error` key?" — and called
    everything else `allow`. A review proved what that admits: a body with no `result`
    at all, a `"jsonrpc": "1.0"` document, and an unrelated HTTP error JSON from
    something that is not this gateway all scored as ALLOWED calls. An allow is the
    verdict that lets a malicious row pass, so the loosest possible check sat on the
    most dangerous branch.

    Only a conforming JSON-RPC 2.0 response is now read as a decision. Everything else
    gets one of the four `CLIENT_CODES`, none of which any scenario expects, so every
    one of them scores FAIL rather than quietly becoming a result.
    """
    if response.timed_out:
        return CallOutcome(
            decision="error", reason_code=NO_RESPONSE, error="client timeout"
        )
    if response.status == 0:
        detail = response.body.decode("utf-8", "replace")[:120]
        return CallOutcome(
            decision="error",
            reason_code=NO_RESPONSE,
            error=f"no HTTP status line{f': {detail}' if detail else ''}",
        )

    parsed = response.json()
    if not isinstance(parsed, dict):
        if response.status >= 500:
            return CallOutcome(
                decision="error",
                reason_code=HTTP_FAILURE,
                error=f"HTTP {response.status} with no JSON-RPC body",
            )
        if response.status >= 400:
            # The only shape that means "the HTTP parser refused this". h11 answers a
            # bad request line or a CR in a field value with a bare 4xx and no body;
            # the gateway's own denials are always reason-coded JSON.
            return CallOutcome(
                decision="deny",
                reason_code=TRANSPORT_REJECTED,
                error=f"HTTP {response.status}, refused before the gateway",
            )
        return CallOutcome(
            decision="error",
            reason_code=GATEWAY_RESPONSE_INVALID,
            error=f"HTTP {response.status}, body is not a JSON object",
        )

    body = cast("dict[str, Any]", parsed)
    problem = _malformed(body, response.status, sent_id)
    if problem is not None:
        return CallOutcome(
            decision="error", reason_code=GATEWAY_RESPONSE_INVALID, error=problem
        )

    if "error" in body:
        error = _obj(body["error"])
        code: Any = _obj(error.get("data")).get("reason_code")
        return CallOutcome(
            decision="deny",
            reason_code=str(code) if code is not None else None,
            error=str(error.get("message", "")),
        )
    return CallOutcome(decision="allow", result=body["result"])


def _malformed(body: dict[str, Any], status: int, sent_id: Any) -> str | None:
    """Why this is not a conforming JSON-RPC 2.0 response, or None if it is.

    Every clause here is a shape that previously scored as a decision. `id` must be
    PRESENT but may be null — `edge._error` sends `"id": null` on the denial path,
    which is what the spec allows when the id could not be determined — while a
    SUCCESS must carry back the id that was sent, since a result a client cannot
    correlate is the defect unit 08 was built to stop shipping.
    """
    if body.get("jsonrpc") != "2.0":
        return f"jsonrpc is {body.get('jsonrpc')!r}, not '2.0'"
    if "id" not in body:
        return "no id: a client cannot correlate this reply"

    has_result, has_error = "result" in body, "error" in body
    if has_result == has_error:
        both = "both result and error" if has_result else "neither result nor error"
        return f"a JSON-RPC response carries exactly one of them; this has {both}"

    if has_error:
        error = _obj(body["error"])
        if not isinstance(error.get("code"), int) or not isinstance(
            error.get("message"), str
        ):
            return f"error object is malformed: {error!r}"
        if not 400 <= status < 500:
            # `wire_shape` maps every ReasonCode to a 4xx. A JSON-RPC error under any
            # other status means the two layers disagree about what happened.
            return f"JSON-RPC error returned under HTTP {status}"
        return None

    if status != 200:
        return f"JSON-RPC result returned under HTTP {status}"
    if sent_id is not _UNKNOWN_ID and body["id"] != sent_id:
        return f"result id {body['id']!r} does not match the request id {sent_id!r}"
    return None


class _UnknownId:
    """Sentinel: the request's own id could not be read, so it cannot be compared.

    Distinct from `None`, which is a legitimate JSON-RPC id. Applies to `raw_body`
    rows, whose whole point is a body that does not parse.
    """


_UNKNOWN_ID: Final = _UnknownId()


def _sent_jsonrpc_id(body: bytes) -> Any:
    try:
        parsed = json.loads(body)
    except ValueError:
        return _UNKNOWN_ID
    if not isinstance(parsed, dict) or "id" not in parsed:
        return _UNKNOWN_ID
    return cast("dict[str, Any]", parsed)["id"]


def _join(events: list[Any]) -> AuditJoin:
    """HARN-009's join, from the events this one call appended.

    Only `request` events count. A `tools/call` also writes an `upstream_attempt`
    (AUDIT-009) and the upstream may write a fault record, and counting those would
    make a perfectly correlated allow look ambiguous.
    """
    requests = [e for e in events if getattr(e, "event_type", None) == "request"]
    if len(requests) != 1:
        return AuditJoin(count=len(requests))
    event = requests[0]
    return AuditJoin(
        count=1,
        request_id=getattr(event, "request_id", None),
        reason_code=getattr(event, "reason_code", None),
        outcome=getattr(event, "outcome", None),
    )


def _obj(value: Any) -> dict[str, Any]:
    """A JSON object, or an empty one. The reply is attacker-influenced in exactly the
    same way a tool result is, so every level of it is checked rather than indexed."""
    return cast("dict[str, Any]", value) if isinstance(value, dict) else {}


@contextmanager
def protected(configs: Mapping[str, Path]) -> Generator[ProtectedClient]:
    """Bring up one gateway per principal and yield a client that dispatches to them.

    Synchronous on the outside because `Client.call` is, and `Client.call` is because
    `runner.run_corpus` is an ordinary loop that must stay readable — the corpus is a
    deliverable people read. `start_blocking_portal` is anyio's own bridge for exactly
    this: one background event loop that outlives individual calls, so the children
    are spawned and handshaken ONCE for the whole corpus instead of per scenario.

    Every gateway is fully torn down on exit, children included, because
    `startup.serve` owns `bridge.upstream`.
    """
    with (
        start_blocking_portal() as portal,
        portal.wrap_async_context_manager(_gateways(configs)) as endpoints,
    ):
        yield ProtectedClient(portal, endpoints)


@asynccontextmanager
async def _gateways(configs: Mapping[str, Path]) -> AsyncGenerator[dict[str, Endpoint]]:
    """Enter every `startup.serve`, then serve them all from one task group.

    ORDER IS LOAD-BEARING. The serve contexts are entered FIRST and the task group
    LAST, so unwinding stops the HTTP servers before the deps they route into are
    torn down. Entering the task group first would close the child processes while
    uvicorn was still accepting requests for them.
    """
    import uvicorn

    from gateway import startup
    from gateway.edge import build_app
    from gateway.pipeline import handle
    from harness.oracle import assert_serialised

    async with AsyncExitStack() as stack:
        endpoints: dict[str, Endpoint] = {}
        servers: list[uvicorn.Server] = []

        for principal, config_path in configs.items():
            # The oracle correlates by byte offset into one shared operation log, which
            # is only valid while upstream calls are serialised. Checked BEFORE the
            # child is spawned — `load_all` validates without launching anything — so a
            # bad config fails with its own message instead of surfacing as a nested
            # ExceptionGroup wrapped in ROUTE_UPSTREAM_UNAVAILABLE from the teardown.
            cfg, _ = startup.load_all(config_path)
            assert_serialised(cfg.edge.max_concurrent_requests)
            deps = await stack.enter_async_context(startup.serve(config_path))
            endpoints[principal] = Endpoint(
                principal=principal,
                port=deps.config.edge.port,
                mcp_path=deps.config.edge.mcp_path,
                audit_path=Path(deps.config.audit.path),
                # Strictly slower than every budget the gateway enforces on itself,
                # for the same reason `edge.HANDLER_BACKSTOP` is: whichever deadline
                # fires first owns the outcome, and a client-side one owns it with no
                # reason code. The margin covers process scheduling on a co-located
                # run, where the gateway, OPA, the child and this client share a CPU.
                response_timeout_s=(
                    deps.config.edge.request_timeout_s * HANDLER_BACKSTOP + 15.0
                ),
            )
            servers.append(
                uvicorn.Server(
                    uvicorn.Config(
                        build_app(deps.config.edge, partial(handle, deps=deps)),
                        host=deps.config.edge.host,
                        port=deps.config.edge.port,
                        log_level="error",  # access logs would echo paths into stderr
                        access_log=False,
                    )
                )
            )

        task_group = await stack.enter_async_context(anyio.create_task_group())
        for server in servers:
            task_group.start_soon(server.serve)
        with anyio.fail_after(30):
            for server in servers:
                while not getattr(server, "started", False):
                    await anyio.sleep(0.05)

        try:
            yield endpoints
        finally:
            for server in servers:
                server.should_exit = True


# -- deployment ------------------------------------------------------------


def write_configs(
    principals: tuple[str, ...],
    *,
    source: Path,
    work: Path,
    fixture_root: Path,
    opa_url: str,
) -> dict[str, Path]:
    """One gateway config per principal, all derived from the SHIPPED config.

    Rewritten rather than hand-written: a config composed here would exercise roots,
    decoys and ceilings that nobody deploys, and the corpus would then be evidence
    about a configuration that does not exist. Only four things vary — the identity,
    the port, the fixture location and the audit destination.

    `roles = [principal]` matches `policies/rego/gateway/grants.rego`, where the grant
    table is keyed by the same three names. `role_vocabulary` is left alone: it is the
    closed set, not a per-principal value, and rewriting it would let a typo in a
    principal name pass validation instead of failing startup.

    `max_concurrent_requests` drops from the shipped 4 to 1, and that is a harness
    requirement rather than a tuning choice: the oracle correlates fixture operations
    to scenarios by byte offset into a single operation log, which two in-flight calls
    would interleave. `assert_serialised` refuses to start a gateway without it.
    """
    text = source.read_text("utf-8")
    posix = str(fixture_root).replace("\\", "/")
    text = text.replace('base = "var/fixture"', f"base = {json.dumps(str(fixture_root))}")
    text = text.replace('path = "var/fixture/', f'path = "{posix}/')
    text = text.replace("http://127.0.0.1:8181", opa_url)

    out: dict[str, Path] = {}
    for principal in principals:
        audit = work / f"audit-{principal}.jsonl"
        # Per-principal audit files. One shared file would have three `AuditSink`
        # handles appending to it from one process, and interleaved partial lines are
        # exactly the corruption the completeness ratio exists to detect — a harness
        # artefact that reads as a gateway defect.
        body = (
            text.replace(
                'principal = "developer"', f"principal = {json.dumps(principal)}"
            )
            .replace('roles = ["developer"]', f"roles = [{json.dumps(principal)}]")
            .replace("port = 8080", f"port = {free_port()}")
            .replace("max_concurrent_requests = 4", "max_concurrent_requests = 1")
            .replace('path = "var/audit.jsonl"', f"path = {json.dumps(str(audit))}")
        )
        path = work / f"gateway-{principal}.toml"
        path.write_text(body, encoding="utf-8")
        out[principal] = path
    return out


__all__ = [
    "ALLOW_DIRECT_ENV",
    "NO_RESPONSE",
    "TRANSPORT_REJECTED",
    "CallOutcome",
    "Client",
    "DirectClient",
    "Endpoint",
    "ProtectedClient",
    "protected",
    "write_configs",
]
