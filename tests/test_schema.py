import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg.schema import (  # noqa: E402
    PROMPT,
    TOOL_CALL,
    new_event,
    validate_event,
)


def test_new_event_fills_base_fields():
    event = new_event(PROMPT, role="user", text="hi")
    for field in ("v", "id", "ts", "mono", "type"):
        assert field in event
    assert event["type"] == PROMPT
    assert event["role"] == "user"
    assert isinstance(event["id"], str) and len(event["id"]) == 32


def test_validate_event_accepts_valid():
    assert validate_event(new_event(TOOL_CALL, step=1, tool="t", args={})) == []


def test_validate_event_reports_missing_fields():
    event = new_event(TOOL_CALL, step=1, tool="t", args={})
    del event["tool"]
    problems = validate_event(event)
    assert any("tool" in p for p in problems)


def test_validate_event_rejects_unknown_type():
    event = new_event("teleport", x=1)
    problems = validate_event(event)
    assert any("unknown event type" in p for p in problems)


def test_validate_event_accepts_unknown_type_with_flag():
    """Forward-compat: allow_unknown_types keeps base-field checks."""
    event = new_event("teleport", x=1)
    assert validate_event(event, allow_unknown_types=True) == []
    del event["ts"]
    problems = validate_event(event, allow_unknown_types=True)
    assert any("ts" in p for p in problems)


def test_validate_event_rejects_non_dict():
    assert validate_event([1, 2, 3]) == ["event is not a JSON object"]
