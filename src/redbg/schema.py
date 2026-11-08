"""Event schema for redbg session traces.

A trace is a JSONL file: one JSON object per line, each a complete event.
The schema is intentionally small. Unknown event types are preserved on load
(forward compatibility) but ignored by the step engine.
"""

from __future__ import annotations

import json
import time
import uuid
from datetime import datetime, timezone

SCHEMA_VERSION = 1

# Nesting depth past which redbg stops walking a value. Deeper subtrees are
# replaced by a marker (or, when redacting, by [REDACTED] — what can't be
# inspected can't be shared). Keeps every recursive walk far below Python's
# recursion limit, including on 3.9 where comprehensions add frames.
MAX_NESTING = 100
TOO_DEEP = "[redbg: nested too deeply]"

SESSION_START = "session_start"
PROMPT = "prompt"
RESPONSE = "response"
TOOL_CALL = "tool_call"
TOOL_RESULT = "tool_result"
NOTE = "note"
USAGE = "usage"
SESSION_END = "session_end"

EVENT_TYPES = frozenset(
    {SESSION_START, PROMPT, RESPONSE, TOOL_CALL, TOOL_RESULT, NOTE, USAGE, SESSION_END}
)

# Fields every event carries.
_BASE_FIELDS = ("v", "id", "ts", "mono")

# Required fields per event type (beyond the base fields).
_REQUIRED = {
    SESSION_START: ("agent",),
    PROMPT: ("role", "text"),
    RESPONSE: ("text",),
    TOOL_CALL: ("step", "tool", "args"),
    TOOL_RESULT: ("step", "call_id", "tool", "ok"),
    NOTE: ("text",),
    USAGE: ("input_tokens", "output_tokens"),
    SESSION_END: ("status",),
}


def utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def new_event(event_type: str, **fields) -> dict:
    """Build a new event dict with base fields filled in."""
    event = {
        "v": SCHEMA_VERSION,
        "id": uuid.uuid4().hex,
        "ts": utcnow_iso(),
        "mono": time.monotonic(),
    }
    event["type"] = event_type
    event.update(fields)
    return event


def validate_event(event: dict, allow_unknown_types: bool = False) -> list[str]:
    """Return a list of validation problems (empty = valid).

    With ``allow_unknown_types`` set, events with a type outside the v1
    schema are accepted (base fields are still required): this is the
    forward-compatibility promise — a newer recorder's event types must
    load in an older reader and be ignored by the step engine.
    """
    problems: list[str] = []
    if not isinstance(event, dict):
        return ["event is not a JSON object"]
    for field in _BASE_FIELDS:
        if field not in event:
            problems.append(f"missing base field: {field}")
    etype = event.get("type")
    if etype not in EVENT_TYPES:
        if allow_unknown_types:
            return problems  # preserved on load; the step engine ignores it
        problems.append(f"unknown event type: {etype!r}")
        return problems
    for field in _REQUIRED[etype]:
        if field not in event:
            problems.append(f"missing required field for {etype}: {field}")
    return problems


def hashable_id(value):
    """``value`` usable as a dict key. Ids come from untrusted traces, so a
    list or object (``"call_id": []``) must not crash indexing: it is keyed by
    its JSON text instead (two equal lists still match each other)."""
    try:
        hash(value)
        return value
    except TypeError:
        return ("unhashable", json.dumps(value, sort_keys=True, default=str))


def is_step_event(event: dict) -> bool:
    return event.get("type") in (TOOL_CALL, TOOL_RESULT)
