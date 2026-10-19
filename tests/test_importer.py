import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg import Session, import_events  # noqa: E402
from redbg.importer import import_file  # noqa: E402


def _otel_spans():
    return [
        {
            "name": "llm.chat",
            "startTime": "2026-10-19T10:00:00Z",
            "endTime": "2026-10-19T10:00:01Z",
            "attributes": {"output": "let me read the file"},
        },
        {
            "name": "tool.read_file",
            "startTime": "2026-10-19T10:00:02Z",
            "endTime": "2026-10-19T10:00:03Z",
            "attributes": {
                "tool.name": "read_file",
                "tool.args": {"path": "x.py"},
                "tool.output": "print(1)",
            },
        },
    ]


def test_import_otel_spans():
    events = import_events(_otel_spans())
    types = [e["type"] for e in events]
    assert types == [
        "session_start",
        "response",
        "tool_call",
        "tool_result",
        "session_end",
    ]
    call = next(e for e in events if e["type"] == "tool_call")
    assert call["tool"] == "read_file"
    assert call["args"] == {"path": "x.py"}
    assert call["step"] == 1
    result = next(e for e in events if e["type"] == "tool_result")
    assert result["ok"] is True
    assert result["output"] == "print(1)"


def test_import_langfuse_observations():
    obj = {
        "observations": [
            {
                "type": "GENERATION",
                "name": "gpt-x",
                "input": "hi",
                "output": "hello",
                "startTime": "2026-10-19T10:00:00Z",
            },
            {
                "type": "SPAN",
                "name": "tool.exec",
                "input": {"cmd": "ls"},
                "output": "a b",
                "startTime": "2026-10-19T10:00:01Z",
            },
        ]
    }
    events = import_events(obj)
    gen = next(e for e in events if e["type"] == "response")
    assert gen["text"] == "hello"
    call = next(e for e in events if e["type"] == "tool_call")
    assert call["tool"] == "exec"
    assert call["args"] == {"cmd": "ls"}


def test_import_traces_wrapper_and_unknown_spans_become_notes():
    obj = {
        "traces": [
            {
                "spans": [
                    {"name": "mystery-span", "attributes": {"k": "v"}},
                ]
            }
        ]
    }
    events = import_events(obj)
    note = next(e for e in events if e["type"] == "note")
    assert "mystery-span" in note["text"]


def test_import_string_args_parsed_as_json():
    events = import_events(
        [
            {"name": "tool.echo", "attributes": {"tool.args": '{"a": 1}'}},
        ]
    )
    call = next(e for e in events if e["type"] == "tool_call")
    assert call["args"] == {"a": 1}


def test_import_file_round_trip(tmp_path):
    src = tmp_path / "spans.json"
    dst = tmp_path / "out.jsonl"
    src.write_text(json.dumps(_otel_spans()))
    stats = import_file(str(src), str(dst))
    assert stats["steps"] == 1
    session = Session.load(str(dst))
    assert len(session.steps) == 1
    assert session.steps[0].tool == "read_file"


def test_import_rejects_garbage():
    try:
        import_events(42)
    except ValueError as exc:
        assert "expects a JSON object or list" in str(exc)
    else:
        raise AssertionError("should have raised")
