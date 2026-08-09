"""Scenario -> wire form. How a corpus row becomes bytes and headers.

Split out of the clients because the `layer = "protocol"` class needs to send
requests no conforming client would build: a header that names a different tool than
the body, a duplicated routing header, a body with no envelope metadata. A client
that could not produce those could not test for them.

Imports `gateway.types` for the envelope shape only. This is the harness, not the
fixture — the rule that forbids sharing code with the gateway (FIX-002) protects the
ORACLE, so that a gateway bug cannot mask itself in the thing observing the gateway.
Nothing here observes anything; it only constructs input.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from mcp.shared.inbound import NAME_BEARING_METHODS, encode_header_value
from mcp_types import (
    CLIENT_CAPABILITIES_META_KEY,
    CLIENT_INFO_META_KEY,
    PROTOCOL_VERSION_META_KEY,
)

from gateway.types import RawEnvelope
from harness.scenario import Scenario, Transport

PROTOCOL_VERSION = "2026-07-28"


def build_envelope(
    scenario: Scenario, *, version: str = PROTOCOL_VERSION, request_id: str | None = None
) -> RawEnvelope:
    """A conforming 2026-07-28 request for `scenario`, then whatever it breaks.

    The default is always valid. A protocol scenario states the ONE thing it damages,
    so a row that fails cannot be failing for an incidental second reason — which is
    the difference between a corpus and a pile of broken requests.
    """
    t = scenario.transport or Transport()
    method = "tools/call"

    meta: dict[str, Any] = {
        PROTOCOL_VERSION_META_KEY: t.body_version or version,
        CLIENT_CAPABILITIES_META_KEY: {},
        CLIENT_INFO_META_KEY: {"name": "ztmg-harness", "version": "1"},
    }
    for key in t.drop_meta:
        meta.pop(key, None)

    params: dict[str, Any] = {
        "_meta": meta,
        "name": scenario.tool,
        "arguments": dict(scenario.arguments),
        **t.body_extra,
    }
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    raw = t.raw_body.encode() if t.raw_body is not None else json.dumps(body).encode()

    name_key = NAME_BEARING_METHODS.get(t.header_method or method)
    pairs: list[tuple[str, str]] = [
        ("mcp-protocol-version", t.header_version or version),
        ("mcp-method", t.header_method or method),
    ]
    if name_key is not None:
        pairs.append(("mcp-name", encode_header_value(t.header_name or scenario.tool)))

    pairs = [(k, v) for k, v in pairs if k not in t.omit]
    pairs.extend(t.add)

    return RawEnvelope(
        request_id=request_id or uuid.uuid4().hex,
        received_at_ns=time.monotonic_ns(),
        body=raw,
        metadata=tuple(pairs),
    )
