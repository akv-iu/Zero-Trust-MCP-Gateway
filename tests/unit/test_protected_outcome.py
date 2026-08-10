"""What `ProtectedClient` is allowed to call a decision, and what it must not.

Every test here is a shape a review proved was being scored wrongly. The pattern in
all of them is the same and it is worth naming once: **`allow` is the verdict that
lets a malicious row pass**, so the check guarding it must be the strictest in the
harness, not the loosest. It was the loosest — "is there an `error` key?" — and that
admitted a body with no `result`, a JSON-RPC 1.0 document, and an unrelated HTTP error
document from something that was not this gateway.

These are unit tests over hand-built `Response` objects on purpose. The four failure
shapes need a gateway that is broken in four specific ways, and constructing the
response directly is the only way to test them deterministically — a real gateway
that produced any of these would be a bug we would fix rather than a fixture.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from harness.clients import (
    GATEWAY_RESPONSE_INVALID,
    HTTP_FAILURE,
    NO_RESPONSE,
    TRANSPORT_REJECTED,
    AuditJoin,
    CallOutcome,
    _outcome,
    _sent_jsonrpc_id,
)
from harness.runner import Verdict, score
from harness.scenario import Scenario
from harness.wire import Response, post_raw

SENT_ID = 1


def reply(body: Any, status: int = 200) -> Response:
    raw = body if isinstance(body, bytes) else json.dumps(body).encode()
    return Response(status=status, body=raw)


def outcome(body: Any, status: int = 200) -> CallOutcome:
    return _outcome(reply(body, status), SENT_ID)


def ok_result() -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": SENT_ID, "result": {"content": []}}


def ok_error() -> dict[str, Any]:
    return {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": -32020,
            "message": "denied",
            "data": {"reason_code": "POLICY_PATH_NOT_PERMITTED"},
        },
    }


# ===========================================================================
# The two shapes that must still work
# ===========================================================================


def test_a_conforming_success_is_an_allow() -> None:
    out = outcome(ok_result())
    assert out.decision == "allow"
    assert out.reason_code is None


def test_a_conforming_error_is_a_deny_carrying_its_reason_code() -> None:
    out = _outcome(reply(ok_error(), status=400), SENT_ID)
    assert out.decision == "deny"
    assert out.reason_code == "POLICY_PATH_NOT_PERMITTED"


# ===========================================================================
# Shape 1 - invalid gateway response. All of these previously scored `allow`.
# ===========================================================================


@pytest.mark.parametrize(
    ("name", "body"),
    [
        ("no result key", {"jsonrpc": "2.0", "id": SENT_ID}),
        ("jsonrpc 1.0", {"jsonrpc": "1.0", "id": SENT_ID, "result": {}}),
        ("no jsonrpc key", {"id": SENT_ID, "result": {}}),
        ("no id", {"jsonrpc": "2.0", "result": {}}),
        (
            "both result and error",
            {
                "jsonrpc": "2.0",
                "id": SENT_ID,
                "result": {},
                "error": {"code": -1, "message": "m"},
            },
        ),
        ("unrelated error json", {"error": "upstream proxy failure", "status": 502}),
        (
            "malformed error object",
            {"jsonrpc": "2.0", "id": None, "error": {"msg": "no code"}},
        ),
        ("mismatched result id", {"jsonrpc": "2.0", "id": 999, "result": {}}),
        ("json array", [1, 2, 3]),
        ("bare string", "denied"),
    ],
)
def test_a_non_conforming_body_is_never_a_decision(name: str, body: Any) -> None:
    """None of these may be read as `allow` OR as `deny`.

    A denial would be nearly as dangerous as an allow: it scores PASS on every
    malicious row, so a gateway that had stopped answering properly would look like a
    gateway that was defending well.
    """
    out = outcome(body)
    assert out.decision == "error", f"{name}: scored {out.decision}"
    assert out.reason_code == GATEWAY_RESPONSE_INVALID, f"{name}: {out.reason_code}"


def test_a_jsonrpc_error_under_a_2xx_is_invalid() -> None:
    """`wire_shape` maps every ReasonCode to a 4xx. A 200 carrying an error means the
    HTTP layer and the JSON-RPC layer disagree about what happened."""
    out = _outcome(reply(ok_error(), status=200), SENT_ID)
    assert out.reason_code == GATEWAY_RESPONSE_INVALID


def test_a_jsonrpc_result_under_a_4xx_is_invalid() -> None:
    out = _outcome(reply(ok_result(), status=400), SENT_ID)
    assert out.reason_code == GATEWAY_RESPONSE_INVALID


def test_an_unparseable_request_body_skips_the_id_comparison() -> None:
    """`raw_body` rows exist to send a body that does not parse, so there is no id to
    compare against. The sentinel keeps that apart from a legitimate `null` id."""
    unknown = _sent_jsonrpc_id(b"{not json")
    out = _outcome(reply(ok_result()), unknown)
    assert out.decision == "allow"


# ===========================================================================
# Shapes 2-4 - transport rejection, HTTP failure, no response
# ===========================================================================


def test_a_4xx_with_no_body_is_a_transport_rejection() -> None:
    """h11 answers a CR in a field value with a bare 4xx. This is the ONLY shape that
    means the request never became a gateway request."""
    out = _outcome(Response(status=400, body=b""), SENT_ID)
    assert out.decision == "deny"
    assert out.reason_code == TRANSPORT_REJECTED


def test_an_empty_500_is_an_http_failure_not_a_transport_rejection() -> None:
    """THE REGRESSION. An empty 500 used to score TRANSPORT_REJECTED, which is exactly
    what a row declaring `http_fate = "rejected"` passes on — so a crashed gateway
    satisfied the two rows whose entire purpose is proving the parser refused them."""
    out = _outcome(Response(status=500, body=b""), SENT_ID)
    assert out.reason_code == HTTP_FAILURE
    assert out.reason_code != TRANSPORT_REJECTED


def test_no_status_line_is_no_response() -> None:
    out = _outcome(Response(status=0, body=b""), SENT_ID)
    assert out.reason_code == NO_RESPONSE


def test_a_client_timeout_is_no_response_and_says_so() -> None:
    out = _outcome(Response(status=0, body=b"", timed_out=True), SENT_ID)
    assert out.reason_code == NO_RESPONSE
    assert out.error == "client timeout"


def test_the_four_client_codes_are_distinct() -> None:
    """They were one code. Collapsing any two of them re-opens a hole this file
    exists to keep shut."""
    assert (
        len({TRANSPORT_REJECTED, HTTP_FAILURE, GATEWAY_RESPONSE_INVALID, NO_RESPONSE})
        == 4
    )


# ===========================================================================
# post_raw is bounded
# ===========================================================================


@pytest.mark.anyio
async def test_a_gateway_that_never_answers_fails_one_row_not_the_run() -> None:
    """An unbounded read means one wedged gateway costs every remaining scenario.

    The server here accepts the connection and then says nothing at all, which is what
    `FIXTURE_MODE=hang` and a deadlocked child both look like from the socket.
    """
    import anyio
    import anyio.abc

    async with await anyio.create_tcp_listener(local_host="127.0.0.1") as listener:
        port = int(listener.extra(anyio.abc.SocketAttribute.local_address)[1])

        async def swallow(stream: Any) -> None:
            await anyio.sleep_forever()

        async with anyio.create_task_group() as tg:
            tg.start_soon(listener.serve, swallow)
            # The outer bound is the real assertion: if `post_raw` were unbounded this
            # would hang here rather than returning, which is what one wedged gateway
            # does to a 66-row corpus run.
            with anyio.fail_after(20):
                response = await post_raw(port, "/mcp", b"{}", [], timeout_s=1.0)
            tg.cancel_scope.cancel()

    assert response.timed_out
    assert _outcome(response, SENT_ID).reason_code == NO_RESPONSE


# ===========================================================================
# HARN-009 - the audit join
# ===========================================================================


def _sc(**kw: object) -> Scenario:
    base = {
        "id": "t",
        "class": "malicious",
        "layer": "security",
        "principal": "intern",
        "tool": "read_file",
        "arguments": {"path": "confidential/x"},
        "expected_decision": "deny",
        "expected_reason": "POLICY_PATH_NOT_PERMITTED",
        "expected_side_effect": "none",
        "risk_tier": "R2",
        "notes": "n",
    }
    return Scenario.model_validate({**base, **kw})


def _clean() -> Any:
    from harness.oracle import Observation

    return Observation(ops=(), tree_before="a", tree_after="a")


def _denied(audit: AuditJoin | None) -> CallOutcome:
    return CallOutcome(
        decision="deny", reason_code="POLICY_PATH_NOT_PERMITTED", audit=audit
    )


def test_a_correctly_joined_denial_passes() -> None:
    join = AuditJoin(count=1, request_id="r1", reason_code="POLICY_PATH_NOT_PERMITTED")
    assert score(_sc(), _denied(join), _clean(), "protected").verdict is Verdict.PASS


def test_a_denial_with_no_audit_event_is_indeterminate() -> None:
    """HARN-009, verbatim: a decision that cannot be joined to a record is never a pass.

    Before this landed, the corpus reported 63 passes without reading the audit log at
    all — a gateway that had stopped writing evidence entirely would have scored
    identically, which makes the number a functional result and not evidence.
    """
    r = score(_sc(), _denied(AuditJoin(count=0)), _clean(), "protected")
    assert r.verdict is Verdict.INDETERMINATE
    assert "no audit event" in r.detail


def test_two_audit_events_for_one_request_is_indeterminate() -> None:
    r = score(_sc(), _denied(AuditJoin(count=2)), _clean(), "protected")
    assert r.verdict is Verdict.INDETERMINATE
    assert "cannot attribute" in r.detail


def test_a_record_contradicting_the_reply_is_a_fail_not_indeterminate() -> None:
    """Missing evidence and wrong evidence are different findings. This one is a real
    gateway defect — the client was told one thing and the log says another — so it
    must not hide inside the bucket meant for 'we cannot tell'."""
    join = AuditJoin(count=1, request_id="r1", reason_code="CANON_OUTSIDE_ROOT")
    r = score(_sc(), _denied(join), _clean(), "protected")
    assert r.verdict is Verdict.FAIL
    assert "CANON_OUTSIDE_ROOT" in r.detail


def test_an_allow_with_no_audit_event_is_indeterminate_too() -> None:
    """A side effect the gateway performed and did not record is the completeness hole
    AUDIT-004 measures. HARN-009 is not conditional on the verdict being a denial."""
    from harness.oracle import Effect, Observation

    allowed = _sc(
        **{
            "class": "legitimate",
            "expected_decision": "allow",
            "expected_reason": "POLICY_SCOPED_READ",
            "expected_side_effect": {"op": "read", "path_contains": "public/doc.txt"},
            "arguments": {"path": "public/doc.txt"},
        }
    )
    obs = Observation(
        ops=(Effect("read", "public/doc.txt", "/abs/public/doc.txt", "ok"),),
        tree_before="a",
        tree_after="a",
    )
    out = CallOutcome(decision="allow", audit=AuditJoin(count=0))
    assert score(allowed, out, obs, "protected").verdict is Verdict.INDETERMINATE


def test_direct_mode_is_exempt_because_it_writes_no_audit_log() -> None:
    """`audit=None` means there is no audit source, not that one is missing. Demanding
    records from the undefended baseline would report 66 INDETERMINATE verdicts about
    a log that was never supposed to exist."""
    assert score(_sc(), _denied(None), _clean(), "direct").verdict is Verdict.PASS


def test_a_prohibited_side_effect_still_outranks_a_missing_audit_event() -> None:
    """HARN-007 stays first. You cannot un-leak a file, and 'we could not correlate it'
    must never downgrade the one finding the project exists to surface."""
    from harness.oracle import Effect, Observation

    leaked = Observation(
        ops=(Effect("read", "confidential/x", "/abs/confidential/x", "ok"),),
        tree_before="a",
        tree_after="a",
    )
    r = score(_sc(), _denied(AuditJoin(count=0)), leaked, "protected")
    assert r.verdict is Verdict.CRITICAL
    assert r.is_lying_gateway


# ===========================================================================
# The exit gate
# ===========================================================================


def _report(*verdicts: tuple[str, Verdict]) -> Any:
    from harness.runner import CorpusReport, ScenarioResult

    return CorpusReport(
        mode="protected",
        results=tuple(
            ScenarioResult(sid, "protected", v, "detail") for sid, v in verdicts
        ),
    )


@pytest.mark.parametrize(
    "verdict",
    [Verdict.FAIL, Verdict.FALSE_SUCCESS, Verdict.INDETERMINATE, Verdict.CRITICAL],
)
def test_any_unresolved_malicious_row_fails_the_run(verdict: Verdict) -> None:
    """THE REGRESSION. The old gate was "no prohibited side effects and every
    legitimate row passes", so a run could exit 0 with malicious rows sitting at FAIL
    or INDETERMINATE — the gateway denied things, possibly for the wrong reasons,
    possibly with no record that it did, and CI would have called that green.
    """
    from scripts.run_corpus import protected_exit_code

    report = _report(("legit-1", Verdict.PASS), ("mal-1", verdict))
    assert protected_exit_code(report, {"legit-1"}) == 1, (
        f"a {verdict.value} malicious row must fail the run"
    )


def test_a_clean_run_exits_zero() -> None:
    from scripts.run_corpus import protected_exit_code

    report = _report(("legit-1", Verdict.PASS), ("mal-1", Verdict.PASS))
    assert protected_exit_code(report, {"legit-1"}) == 0


def test_skipped_alone_does_not_fail_the_run() -> None:
    """The one exemption, and it is safe because a skip is printed as a skip and
    counted separately rather than folded into the pass count."""
    from scripts.run_corpus import protected_exit_code

    report = _report(("legit-1", Verdict.PASS), ("mal-1", Verdict.SKIPPED))
    assert protected_exit_code(report, {"legit-1"}) == 0


def test_a_gateway_that_denies_everything_still_fails_the_run() -> None:
    """Zero unresolved verdicts is not sufficient. A gateway that refused every
    request would satisfy the first half of the gate perfectly."""
    from scripts.run_corpus import protected_exit_code

    report = _report(("legit-1", Verdict.FAIL), ("mal-1", Verdict.PASS))
    assert protected_exit_code(report, {"legit-1"}) == 1


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
