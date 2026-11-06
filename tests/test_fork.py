import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg import ForkSpec, Session, fork_session  # noqa: E402
from redbg.fork import LIVE, PLAYBACK  # noqa: E402


def test_playback_fork_reexecutes_tail_with_override(trace_fail):
    session = Session.load(trace_fail)
    seen = []

    def read_file(args):
        seen.append(args["path"])
        return f"contents of {args['path']}"

    spec = ForkSpec(
        at_step=1,
        strategy=PLAYBACK,
        override_args={"path": "fixed.txt"},
        tool_impls={"read_file": read_file, "write_file": lambda args: "wrote it"},
    )
    forked = fork_session(session, spec)
    calls = [e for e in forked.events if e["type"] == "tool_call"]
    # History (nothing before step 1) + 3 re-executed calls.
    assert [c["step"] for c in calls] == [1, 2, 3]
    assert calls[0]["args"] == {"path": "fixed.txt"}  # override applied
    assert calls[1]["args"] == {"path": "b.txt"}  # recorded args kept
    assert seen == ["fixed.txt", "b.txt"]
    results = [e for e in forked.events if e["type"] == "tool_result"]
    assert all(r["ok"] for r in results)
    assert "fixed.txt" in results[0]["output"]


def test_playback_fork_keeps_history_before_fork_point(trace_fail):
    session = Session.load(trace_fail)
    spec = ForkSpec(
        at_step=2,
        strategy=PLAYBACK,
        tool_impls={"read_file": lambda a: "x", "write_file": lambda a: "y"},
    )
    forked = fork_session(session, spec)
    calls = [e for e in forked.events if e["type"] == "tool_call"]
    # Step 1 preserved from history (failed read of a.txt); steps 2.. re-run.
    assert calls[0]["step"] == 1
    first_result = next(
        e
        for e in forked.events
        if e.get("type") == "tool_result" and e.get("step") == 1
    )
    assert first_result["ok"] is False  # original failure preserved


def test_playback_fork_defaults_to_echo_mock(trace_ok):
    session = Session.load(trace_ok)
    forked = fork_session(session, ForkSpec(at_step=1))
    result = next(e for e in forked.events if e.get("type") == "tool_result")
    payload = json.loads(result["output"])
    assert payload["mock"] is True


def test_fork_carries_provenance(trace_ok):
    session = Session.load(trace_ok)
    forked = fork_session(session, ForkSpec(at_step=1, strategy=PLAYBACK))
    meta = forked.events[0]["meta"]
    assert meta["fork"] is True
    assert meta["forked_from"] == session.session_id
    assert meta["at_step"] == 1
    assert meta["strategy"] == PLAYBACK


def test_fork_inject_prompt(trace_ok):
    session = Session.load(trace_ok)
    forked = fork_session(session, ForkSpec(at_step=1, inject_prompt="actually, stop"))
    prompts = [e for e in forked.events if e.get("type") == "prompt"]
    assert prompts[-1]["text"] == "actually, stop"


def test_fork_rejects_bad_step_and_strategy(trace_ok):
    session = Session.load(trace_ok)
    with pytest.raises(ValueError, match="out of range"):
        fork_session(session, ForkSpec(at_step=99))
    with pytest.raises(ValueError, match="unknown strategy"):
        fork_session(session, ForkSpec(at_step=1, strategy="dream"))


def test_live_fork_requires_model_fn(trace_ok):
    session = Session.load(trace_ok)
    with pytest.raises(ValueError, match="model_fn"):
        fork_session(session, ForkSpec(at_step=1, strategy=LIVE))


def test_live_fork_calls_model_until_text(trace_ok):
    session = Session.load(trace_ok)
    script = [
        {"tool": "read_file", "args": {"path": "live.txt"}, "text": "reading"},
        "done reading",
    ]

    def model_fn(messages):
        reply = script.pop(0)
        model_fn.seen = messages
        return reply

    spec = ForkSpec(
        at_step=1,
        strategy=LIVE,
        model_fn=model_fn,
        tool_impls={"read_file": lambda a: "LIVE-CONTENTS"},
    )
    forked = fork_session(session, spec)
    calls = [e for e in forked.events if e["type"] == "tool_call"]
    assert len(calls) == 1 and calls[0]["tool"] == "read_file"
    assert calls[0]["args"] == {"path": "live.txt"}
    results = [e for e in forked.events if e["type"] == "tool_result"]
    assert results[0]["output"] == "LIVE-CONTENTS"
    responses = [e for e in forked.events if e.get("type") == "response"]
    assert responses[-1]["text"] == "done reading"


def test_live_fork_respects_max_steps(trace_ok):
    session = Session.load(trace_ok)

    def model_fn(messages):
        return {"tool": "loop", "args": {}}  # never stops on its own

    spec = ForkSpec(
        at_step=1,
        strategy=LIVE,
        model_fn=model_fn,
        tool_impls={"loop": lambda a: "x"},
        max_steps=3,
    )
    forked = fork_session(session, spec)
    calls = [e for e in forked.events if e["type"] == "tool_call"]
    assert len(calls) == 3
    assert any(
        e.get("type") == "note" and "max_steps" in e.get("text", "")
        for e in forked.events
    )


def test_live_fork_bad_model_reply_raises(trace_ok):
    session = Session.load(trace_ok)
    spec = ForkSpec(
        at_step=1, strategy=LIVE, model_fn=lambda messages: 42, tool_impls={}
    )
    with pytest.raises(ValueError, match="model_fn must return"):
        fork_session(session, spec)


def test_fork_missing_tool_impl_with_mock_disabled_raises(trace_ok):
    session = Session.load(trace_ok)
    spec = ForkSpec(at_step=1, allow_mock=False, tool_impls={})
    with pytest.raises(ValueError, match="no tool implementation"):
        fork_session(session, spec)


def test_fork_save_writes_valid_jsonl(trace_ok, tmp_path):
    session = Session.load(trace_ok)
    forked = fork_session(session, ForkSpec(at_step=1))
    out = str(tmp_path / "fork.jsonl")
    forked.save(out)
    reloaded = Session.load(out)
    assert len(reloaded.steps) == 2
    assert reloaded.events[0]["meta"]["fork"] is True


def test_fork_resolves_step_positionally_not_by_file_field(tmp_path):
    # Hand-edited trace with non-dense step numbering: the fork must still
    # find the 2nd tool call by position.
    import json

    lines = []
    sid = "s1"

    def ev(t, **f):
        base = {
            "v": 1,
            "id": f"e{len(lines)}",
            "ts": "t",
            "mono": 0.0,
            "type": t,
            "session_id": sid,
        }
        base.update(f)
        return base

    lines.append(ev("session_start", agent="x"))
    lines.append(ev("tool_call", step=10, tool="t1", args={}))
    lines.append(
        ev("tool_result", step=10, call_id="e1", tool="t1", ok=True, output="a")
    )
    lines.append(ev("tool_call", step=99, tool="t2", args={}))
    lines.append(
        ev("tool_result", step=99, call_id="e3", tool="t2", ok=True, output="b")
    )
    lines.append(ev("session_end", status="ok", steps=2))
    path = str(tmp_path / "weird.jsonl")
    with open(path, "w") as handle:
        for line in lines:
            handle.write(json.dumps(line) + "\n")

    session = Session.load(path)
    assert [s.n for s in session.steps] == [1, 2]  # renumbered densely
    forked = fork_session(session, ForkSpec(at_step=2))
    calls = [e for e in forked.events if e["type"] == "tool_call"]
    assert [c["step"] for c in calls] == [1, 2]
    assert calls[0]["tool"] == "t1"  # history preserved positionally
    assert calls[1]["tool"] == "t2"


def test_live_fork_warns_when_model_makes_no_calls(tmp_path):
    from conftest import record_session

    path = record_session(str(tmp_path / "s.jsonl"))
    session = Session.load(path)
    spec = ForkSpec(
        at_step=1,
        strategy=LIVE,
        model_fn=lambda messages: "no tools needed",
        override_args={"x": 1},
    )
    forked = fork_session(session, spec)
    notes = [e for e in forked.events if e.get("type") == "note"]
    assert any("override_args had no effect" in n["text"] for n in notes)


def test_playback_fork_carries_unknown_events_verbatim(tmp_path):
    """Unknown event types survive a fork: carried verbatim, not dropped."""
    import json as _json

    from redbg.schema import (
        SESSION_END,
        SESSION_START,
        TOOL_CALL,
        TOOL_RESULT,
        new_event,
    )

    lines = [
        new_event(SESSION_START, session_id="s", agent="a"),
        new_event("teleport", x=1, id="t1"),
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
    path = str(tmp_path / "future.jsonl")
    with open(path, "w") as fh:
        for ev in lines:
            fh.write(_json.dumps(ev) + "\n")
    session = Session.load(path)
    forked = fork_session(session, ForkSpec(at_step=1, strategy=PLAYBACK))
    carried = [e for e in forked.events if e.get("type") == "teleport"]
    assert len(carried) == 1
    assert carried[0]["x"] == 1
