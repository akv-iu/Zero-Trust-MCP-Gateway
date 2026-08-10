"""08 - Upstream response validation and bounding.

Spec: _specs/08-svc-response-guard.md   Tech: _tech/08-svc-response-guard.md

The return path is untrusted too. A tool result is attacker-influenced content: it can
be oversized, pathologically shaped, or carry text engineered to read as instructions
to whatever consumes it next. This unit bounds it and labels it. It does not clean it.

WHO ACTUALLY CORRELATES, stated plainly because `_tech/08` §2 asks for exactly this and
because claiming otherwise would be the easiest false claim in the project to make.

**The SDK correlates, not this module.** `JSONRPCDispatcher` matches every response to
an outbound request by its `_pending` key, and a response whose id matches nothing is
dropped with a `logger.debug` — no exception, no callback, no stream event. Measured
against the pinned SDK with `FIXTURE_MODE=wrong_id`: the in-flight call receives no
answer at all and dies on unit 07's obligation timeout as `ROUTE_TIMEOUT`. The security
property RESP-001 asks for therefore holds — a mismatched response is never delivered —
while `RESP_CORRELATION_MISMATCH` had no way to be raised, so it was removed rather
than documented (`gateway/errors.py` carries the finding and its revival trigger).

`FIXTURE_MODE=malformed` behaves the same way from the caller's side: the line fails to
parse inside the SDK's reader, and the request hangs into the same timeout. What the
SDK *does* offer is `message_handler`, which receives transport-level exceptions, so
`UpstreamWatch` below turns that silence into an audit record even though it cannot
turn it into a faster failure.

WHAT THIS MODULE DOES OWN: the size ceiling on the parsed structure, the structural
limits, the shape check, MRTR refusal, and the untrusted label. Those are the paths a
well-formed-but-hostile upstream actually takes, and they are all reachable —
`oversized`, `pathological` and `inject` all arrive here as ordinary results.
"""

from __future__ import annotations

from collections.abc import Mapping
from contextlib import suppress
from datetime import UTC, datetime
from typing import Any, Final, cast

import mcp_types

from gateway import protocol
from gateway.audit_schema import UpstreamFaultEvent
from gateway.config import ResponseConfig
from gateway.errors import ProtocolDenial, ReasonCode, ResponseDenial
from gateway.types import (
    CanonicalRequest,
    JsonObject,
    Obligations,
    RawResult,
    Untrusted,
)

_LIST_METHOD: Final = "tools/list"

#: What a valid result for each allowed method must carry. The method allowlist is
#: unit 02's, so this table is complete by construction rather than by vigilance.
_REQUIRED_LIST_KEY: Final[dict[str, str]] = {
    "tools/call": "content",
    _LIST_METHOD: "tools",
}


def validate(
    raw: RawResult, req: CanonicalRequest, ob: Obligations, cfg: ResponseConfig
) -> Untrusted[JsonObject]:
    """Accept, bound, label. MUST NOT mutate accepted content (RESP-008).

    Order matters and it is cheapest-first for a reason: the size check is a single
    integer comparison against a count unit 07 already took, so a 100 MiB response is
    refused before anything walks it. Walking first would make the structural limits
    the very denial-of-service they exist to prevent.

    Nothing here rewrites. There is no truncation path, no redaction, no reordering:
    a response that does not fit is an error, full stop (RESP-005's "never delivered
    truncated as complete" is satisfied by raising rather than trimming). That is also
    what keeps the oracle's job possible — the harness compares what the fixture
    produced against what the client received, and any gateway-side rewriting would
    break that correspondence (`_tech/08` §4).
    """
    doc = _envelope(raw)
    _bound(raw, ob, cfg)
    _shape(doc, req)
    _limits(doc, cfg)
    # RESP-001, and it is what the client actually needs: a JSON-RPC RESPONSE, not the
    # bare MCP result. The edge used to write `json.dumps(result.unwrap())` straight to
    # the wire, so every successful reply lacked `jsonrpc`, `id` and `result` and no
    # conforming client could have correlated one — while every DENIAL was correctly
    # framed by `edge._error`, which is what kept it hidden (review finding). The
    # envelope is built here because this is the stage that holds the request, and
    # `_tech/08` §1 already put `_shape(raw, req)` at exactly this point.
    #
    # RESP-008 is untouched by it: `doc` is placed under `result` unchanged, not
    # rewritten. `Untrusted` wraps rather than copies, so byte-for-byte identity with
    # what the upstream sent stays a property of the type.
    return Untrusted({"jsonrpc": "2.0", "id": req.jsonrpc_id, "result": doc})


def _envelope(raw: RawResult) -> JsonObject:
    """RESP-001's local half: the result is a JSON object, or it is nothing.

    The SDK has already validated the JSON-RPC frame around it — this is the payload
    inside, which unit 07 dumped from the SDK's model. A non-object here means the
    router handed on something that is not an MCP result at all.
    """
    content: Any = raw.content
    if not isinstance(content, Mapping):
        raise _deny(
            ReasonCode.RESP_ENVELOPE_INVALID,
            f"result is {type(content).__name__}, not an object",
        )
    return dict(cast("Mapping[str, Any]", content))


def _bound(raw: RawResult, ob: Obligations, cfg: ResponseConfig) -> None:
    """RESP-003. Two ceilings, and the lower one wins.

    `ob.max_response_bytes` is what policy authorised for THIS request; `cfg.max_bytes`
    is what the gateway will carry for any request. Unit 07 already compared against
    the obligation, and this comparison is deliberately not "the same check twice":
    unit 07 bounds what the transport delivered, this bounds what survived parsing,
    and only the second catches a payload that expands after framing (`_tech/08` §3).

    Both are cheap. Redundancy between two layers that fail differently is the point.
    """
    ceiling = min(ob.max_response_bytes, cfg.max_bytes)
    if raw.byte_count > ceiling:
        raise _deny(ReasonCode.RESP_TOO_LARGE, f"{raw.byte_count} bytes over {ceiling}")


def _shape(doc: JsonObject, req: CanonicalRequest) -> None:
    """The result carries what the method it answers is supposed to carry.

    MRTR first (ADR-001 §5). A result containing `inputRequests` is the server asking
    the client to gather more input and retry — a fresh authorization decision wearing
    a response's clothes, since the retry carries the original params PLUS new content.
    v1 refuses it explicitly rather than passing it through untested. `bridge.call_tool`
    passes `allow_input_required=True` for exactly this reason: with the SDK's default
    the same response raises a bare `RuntimeError` that would reach the pipeline as
    INTERNAL_ERROR, which denies for the right reason under the wrong name.
    """
    if "inputRequests" in doc:
        raise _deny(ReasonCode.RESP_MRTR_UNSUPPORTED, req.method)
    required = _REQUIRED_LIST_KEY.get(req.method)
    if required is None:
        # Unreachable while unit 02's allowlist is the only way in, and a denial
        # rather than a pass because "I do not know what this method's result should
        # look like" is not a reason to relay it (RESP-007).
        raise _deny(ReasonCode.RESP_SHAPE_INVALID, f"no result shape for {req.method}")
    if not isinstance(doc.get(required), list):
        raise _deny(
            ReasonCode.RESP_SHAPE_INVALID, f"{req.method} result has no {required!r} list"
        )


def _limits(doc: JsonObject, cfg: ResponseConfig) -> None:
    """RESP-004, on unit 02's walk (`_tech/08` §1 forbids a second one).

    The walk raises with the caller's reason code, so the translation below is only
    needed for the exception TYPE — `ProtocolDenial` names stage 02 and this failure
    happened at stage 08, which is what the audit record's stage timing would otherwise
    misattribute.
    """
    try:
        protocol.check_limits(doc, cfg, ReasonCode.RESP_LIMIT_EXCEEDED)
    except ProtocolDenial as e:
        raise _deny(ReasonCode.RESP_LIMIT_EXCEEDED, e.detail or "structural limit") from e


# ===========================================================================
# Out-of-band observation (RESP-002)
# ===========================================================================


class UpstreamWatch:
    """Records what the upstream says that no request asked for.

    RESP-002 requires an unsolicited upstream message to be dropped AND audited. The
    dropping is structural and needs no code: `pipeline.handle` only ever returns what
    `router.route` returned, so a server-initiated message has no path to the client
    whatever this class does. What was missing is the audit — without it the fixture's
    `unsolicited` mode produced a completely ordinary success and the fact that the
    child had tried to make the gateway act was recorded nowhere.

    The three callbacks below are the SDK's own hooks for server-to-client requests,
    and the SDK's defaults ALREADY refuse all three. Ours refuse identically and write
    a record first. `sampling/createMessage` is the one to read twice: a compromised
    child asking the gateway to run a prompt through a model is the S-2 surface, and in
    v1.1 that model is reachable. It is refused here and the refusal is evidence.

    Not registered by default. `bridge.upstream` takes one when a caller has a sink to
    write to, which in practice is `startup.serve`.
    """

    def __init__(self, sink: Any, server_id: str) -> None:
        self._sink = sink
        self._server_id = server_id

    async def on_message(self, message: Any) -> None:
        """The SDK's `message_handler`: notifications, and transport-level faults.

        A fault here is how `FIXTURE_MODE=malformed` becomes visible at all. It does
        not rescue the request — the SDK has already dropped the unparseable line and
        the caller will time out — but it turns "the upstream went quiet" into "the
        upstream sent us something unparseable at this moment", which is the
        difference between an unexplained timeout and a finding.
        """
        if isinstance(message, Exception):
            await self._record(
                ReasonCode.RESP_ENVELOPE_INVALID,
                # The CLASS NAME only. A pydantic ValidationError's message quotes the
                # input it rejected, so recording `str(e)` would put upstream response
                # bytes into the audit log through the field meant to describe a
                # failure (RESP-009, CONV-012).
                fault=type(message).__name__,
            )
            return
        await self._record(
            ReasonCode.RESP_UNSOLICITED, method=_method_of(message), fault="notification"
        )

    async def refuse_roots(self, context: Any) -> Any:
        return await self._refuse("roots/list")

    async def refuse_sampling(self, context: Any, params: Any) -> Any:
        return await self._refuse("sampling/createMessage")

    async def refuse_elicitation(self, context: Any, params: Any) -> Any:
        return await self._refuse("elicitation/create")

    async def _refuse(self, method: str) -> Any:
        await self._record(ReasonCode.RESP_UNSOLICITED, method=method)
        return mcp_types.ErrorData(
            code=mcp_types.INVALID_REQUEST,
            message="Server-initiated requests are not accepted by this gateway.",
        )

    async def _record(
        self, code: ReasonCode, *, method: str | None = None, fault: str | None = None
    ) -> None:
        """Best-effort by design, and this is the one place in the project where that
        is right: this runs on the SDK's own read loop, outside any request, so raising
        would tear down the session over a message the gateway already refused. A
        request's OWN evidence is still a hard dependency (AUDIT-009); this is evidence
        about the upstream, and losing it must not take the connection with it."""
        with suppress(Exception):  # see the docstring
            await self._sink.write(
                UpstreamFaultEvent(
                    ts=datetime.now(UTC),
                    server_id=self._server_id,
                    reason_code=code.value,
                    mcp_method=method,
                    fault=fault,
                )
            )


def _method_of(message: Any) -> str | None:
    root = getattr(message, "root", message)
    method = getattr(root, "method", None)
    return method if isinstance(method, str) else None


def _deny(code: ReasonCode, detail: str) -> ResponseDenial:
    return ResponseDenial(code, detail=detail)


__all__ = ["UpstreamWatch", "validate"]
