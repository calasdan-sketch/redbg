import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg import Navigator, Session  # noqa: E402


def test_load_pairs_calls_and_results(trace_ok):
    session = Session.load(trace_ok)
    assert len(session.steps) == 2
    assert session.steps[0].tool == "read_file"
    assert session.steps[0].ok is True
    assert session.steps[0].output == "contents of a"
    assert session.steps[1].tool == "write_file"


def test_step_duration_uses_monotonic_clock(trace_ok):
    step = Session.load(trace_ok).steps[0]
    assert step.duration_ms is not None
    assert step.duration_ms >= 0.0


def test_step_context_is_nearest_prompt_and_response(trace_ok):
    session = Session.load(trace_ok)
    step = session.steps[0]
    assert step.prompt_ctx["text"] == "do the thing"
    assert step.response_ctx["text"] == "on it"


def test_get_step_out_of_range(trace_ok):
    session = Session.load(trace_ok)
    with pytest.raises(IndexError, match="out of range"):
        session.get_step(99)


def test_malformed_json_raises_with_line_number(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(
        '{"v":1,"id":"a","ts":"t","mono":0,"type":"session_start",'
        '"agent":"x"}\nnot json\n'
    )
    with pytest.raises(ValueError, match=r"bad\.jsonl:2"):
        Session.load(str(path))


def test_skip_bad_salvages_crashed_recording(tmp_path):
    path = tmp_path / "bad.jsonl"
    path.write_text(
        '{"v":1,"id":"a","ts":"t","mono":0,"type":"session_start",'
        '"agent":"x"}\nGARBAGE\n'
        '{"v":1,"id":"b","ts":"t","mono":1,"type":"tool_call",'
        '"step":1,"tool":"t","args":{}}\n'
    )
    session = Session.load(str(path), skip_bad=True)
    assert len(session.steps) == 1


def test_orphan_result_becomes_visible_step(tmp_path):
    path = tmp_path / "orphan.jsonl"
    path.write_text(
        '{"v":1,"id":"r","ts":"t","mono":2,"type":"tool_result",'
        '"step":7,"call_id":"zzz","tool":"ghost","ok":true,'
        '"output":"hi"}\n'
    )
    session = Session.load(str(path))
    assert len(session.steps) == 1
    assert session.steps[0].tool == "ghost"
    assert session.steps[0].n == 1  # renumbered densely


def test_navigator_next_prev_boundaries(trace_ok):
    nav = Navigator(Session.load(trace_ok))
    assert nav.current() is None
    assert nav.next().n == 1
    assert nav.next().n == 2
    assert nav.next() is None  # past the end
    assert nav.prev().n == 1
    assert nav.prev() is None  # before the start
    assert nav.cursor == 0


def test_navigator_goto(trace_ok):
    nav = Navigator(Session.load(trace_ok))
    assert nav.goto(2).n == 2
    assert nav.current().n == 2
    with pytest.raises(IndexError):
        nav.goto(5)


def test_search_finds_steps(trace_ok):
    session = Session.load(trace_ok)
    assert session.search("write_file") == [2]
    assert session.search("contents of a") == [1]
    assert session.search("nope-nothing") == []


def test_loads_gzip_transparently(trace_gz):
    assert len(Session.load(trace_gz).steps) == 2


def test_unknown_event_type_preserved_and_ignored(tmp_path):
    """Forward-compat: a newer recorder's event type loads fine and the
    step engine ignores it (blueprint Decision 1)."""
    import json

    from redbg.schema import (
        SESSION_END,
        SESSION_START,
        TOOL_CALL,
        TOOL_RESULT,
        new_event,
    )

    path = str(tmp_path / "future.jsonl")
    lines = [
        new_event(SESSION_START, session_id="s", agent="a"),
        new_event("teleport", x=1),  # a v2 event type this reader doesn't know
        new_event(TOOL_CALL, session_id="s", step=1, tool="t", args={}, id="c1"),
        new_event(
            TOOL_RESULT,
            session_id="s",
            step=1,
            call_id="c1",
            tool="t",
            ok=True,
            output="hi",
        ),
        new_event(SESSION_END, session_id="s", status="ok"),
    ]
    with open(path, "w") as fh:
        for ev in lines:
            fh.write(json.dumps(ev) + "\n")
    session = Session.load(path)
    assert len(session.steps) == 1  # unknown event is not a step
    assert any(e.get("type") == "teleport" for e in session.events)  # but preserved
