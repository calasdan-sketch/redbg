"""Export a session as OTLP/JSON traces (``redbg otel``).

Pure data conversion: nothing is sent anywhere. The JSON can be loaded by any
tool that reads the OpenTelemetry protocol's JSON encoding (for example an
OpenTelemetry Collector file receiver). Tool arguments and outputs are NOT
included unless ``with_args`` is set, and then they are redacted first.

IDs are derived from the session id and step number, so exporting the same
trace twice gives byte-identical output.
"""

from __future__ import annotations

import hashlib
import json

from ._meta import AUTHOR
from .formats import _epoch
from .redact import redact_value


def _hex(seed: str, length: int) -> str:
    return hashlib.sha256(seed.encode("utf-8", "replace")).hexdigest()[:length]


def _attr(key: str, value) -> dict:
    if isinstance(value, bool):
        return {"key": key, "value": {"boolValue": value}}
    if isinstance(value, int):
        return {"key": key, "value": {"intValue": str(value)}}
    if isinstance(value, float):
        return {"key": key, "value": {"doubleValue": value}}
    return {"key": key, "value": {"stringValue": str(value)}}


def _nano(seconds: float) -> str:
    return str(max(0, int(round(seconds * 1e9))))


def session_to_otlp(session, version: str, with_args: bool = False) -> dict:
    """OTLP/JSON ``resourceSpans`` document for ``session``."""
    sid = str(session.session_id or session.path)
    trace_id = _hex("trace:" + sid, 32)
    root_id = _hex("root:" + sid, 16)

    last = 0.0
    spans = []
    first = None
    end_all = 0.0
    for step in session.steps:
        start = _epoch((step.call or {}).get("ts"))
        end = _epoch((step.result or {}).get("ts"))
        if start is None:
            start = end if end is not None else last
        if end is None or end < start:
            end = start
        last = end
        first = start if first is None else min(first, start)
        end_all = max(end_all, end)
        attrs = [
            _attr("redbg.step", step.n),
            _attr("redbg.tool", step.tool),
            _attr("redbg.complete", step.result is not None),
        ]
        if with_args:
            args, _ = redact_value("args", step.args)
            attrs.append(_attr("redbg.args", json.dumps(args, default=str)[:4000]))
        status: dict = {"code": 0}
        if step.ok is True:
            status = {"code": 1}
        elif step.ok is False:
            status = {"code": 2, "message": str(step.error or "tool failed")[:200]}
        spans.append(
            {
                "traceId": trace_id,
                "spanId": _hex(f"step:{sid}:{step.n}", 16),
                "parentSpanId": root_id,
                "name": step.tool,
                "kind": 1,
                "startTimeUnixNano": _nano(start),
                "endTimeUnixNano": _nano(end),
                "attributes": attrs,
                "status": status,
            }
        )
    first = first or 0.0
    root = {
        "traceId": trace_id,
        "spanId": root_id,
        "name": f"agent session ({session.agent})",
        "kind": 1,
        "startTimeUnixNano": _nano(first),
        "endTimeUnixNano": _nano(max(end_all, first)),
        "attributes": [
            _attr("redbg.steps", len(session.steps)),
            _attr("redbg.format", session.format or "unknown"),
        ],
        "status": {"code": 2} if session.status == "error" else {"code": 0},
    }
    return {
        "resourceSpans": [
            {
                "resource": {
                    "attributes": [
                        _attr("service.name", str(session.agent or "unknown")),
                        _attr("telemetry.sdk.name", "redbg"),
                        _attr("telemetry.sdk.version", version),
                        _attr("redbg.publisher", AUTHOR),
                    ]
                },
                "scopeSpans": [
                    {"scope": {"name": "redbg", "version": version}, "spans": [root, *spans]}
                ],
            }
        ]
    }
