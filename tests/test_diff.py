import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg import (  # noqa: E402
    Session,
    align_steps,
    find_divergence,
    render_diff,
)
from redbg.diff import ARGS_CHANGED, TOOL_CHANGED  # noqa: E402
from tests.conftest import record_session  # noqa: E402


def test_identical_sessions_have_no_divergence(trace_ok):
    a = Session.load(trace_ok)
    assert find_divergence(a, a) is None
    report = render_diff(a, a, use_color=False)
    assert "identical" in report


def test_args_change_detected_with_field_diff(tmp_path):
    p1 = record_session(str(tmp_path / "a.jsonl"))
    p2 = str(tmp_path / "b.jsonl")
    record_session(p2)  # same shape; now rewrite step-1 args via fork-like edit
    # Build b2 with a changed arg on step 1 by re-recording manually.
    from redbg import Recorder

    with Recorder(p2, agent="test-agent") as rec:
        rec.prompt("user", "do the thing")
        rec.response("on it", model="test-model")
        c = rec.tool_call("read_file", {"path": "CHANGED.txt"})
        rec.tool_result(c, ok=True, output="contents of a")
        c = rec.tool_call("write_file", {"path": "out.txt", "content": "done"})
        rec.tool_result(c, ok=True, output="wrote 4 bytes")
    a, b = Session.load(p1), Session.load(p2)
    div = find_divergence(a, b)
    assert div is not None
    assert div.kind == ARGS_CHANGED
    assert div.a_n == 1 and div.b_n == 1
    assert "args changed" in div.headline
    assert "CHANGED" in div.detail  # unified field diff present
    report = render_diff(a, b, use_color=False)
    assert "First divergence at A:1 / B:1" in report


def test_tool_change_detected(tmp_path):
    from redbg import Recorder

    p1 = str(tmp_path / "a.jsonl")
    p2 = str(tmp_path / "b.jsonl")
    with Recorder(p1) as rec:
        c = rec.tool_call("read_file", {"path": "x"})
        rec.tool_result(c, ok=True, output="y")
    with Recorder(p2) as rec:
        c = rec.tool_call("exec", {"cmd": "ls"})
        rec.tool_result(c, ok=True, output="y")
    div = find_divergence(Session.load(p1), Session.load(p2))
    assert div.kind == TOOL_CHANGED
    assert "read_file" in div.headline and "exec" in div.headline


def test_status_change_is_first_class_divergence(trace_ok, trace_fail):
    # Same tool, same args — but A succeeded and B failed. That is the
    # classic "it worked on Monday" case and must headline the diff.
    a = Session.load(trace_ok)
    b = Session.load(trace_fail)
    div = find_divergence(a, b)
    assert div is not None
    assert div.kind == "status_changed"
    assert div.a_n == 1 and div.b_n == 1
    assert "succeeded" in div.headline and "FAILED" in div.headline
    report = render_diff(a, b, use_color=False)
    assert "status changed" in report


def test_added_step_reported_at_divergence(tmp_path):
    from redbg import Recorder

    p1 = str(tmp_path / "a.jsonl")
    p2 = str(tmp_path / "b.jsonl")
    with Recorder(p1) as rec:
        c = rec.tool_call("t1", {})
        rec.tool_result(c, ok=True, output="x")
    with Recorder(p2) as rec:
        c = rec.tool_call("t1", {})
        rec.tool_result(c, ok=True, output="x")
        c = rec.tool_call("t2", {})
        rec.tool_result(c, ok=True, output="y")
    a, b = Session.load(p1), Session.load(p2)
    div = find_divergence(a, b)
    assert div is not None
    assert div.a_n is None and div.b_n == 2
    assert "added in B" in div.headline
    report = render_diff(a, b, use_color=False)
    assert "added in B" in report
    assert "A: 1 steps · B: 2 steps" in report


def test_removed_step_reported(tmp_path):
    from redbg import Recorder

    p1 = str(tmp_path / "a.jsonl")
    p2 = str(tmp_path / "b.jsonl")
    with Recorder(p1) as rec:
        for tool in ("t1", "t2"):
            c = rec.tool_call(tool, {})
            rec.tool_result(c, ok=True, output="x")
    with Recorder(p2) as rec:
        c = rec.tool_call("t1", {})
        rec.tool_result(c, ok=True, output="x")
    div = find_divergence(Session.load(p1), Session.load(p2))
    assert div is not None
    assert div.a_n == 2 and div.b_n is None
    assert "removed in B" in div.headline


def test_output_difference_flagged_on_same_steps(tmp_path):
    from redbg import Recorder

    p1 = str(tmp_path / "a.jsonl")
    p2 = str(tmp_path / "b.jsonl")
    with Recorder(p1) as rec:
        c = rec.tool_call("t", {"x": 1})
        rec.tool_result(c, ok=True, output="output-one")
    with Recorder(p2) as rec:
        c = rec.tool_call("t", {"x": 1})
        rec.tool_result(c, ok=True, output="output-two")
    report = render_diff(Session.load(p1), Session.load(p2), use_color=False)
    assert "output DIFFERS" in report


def test_align_steps_classifies_everything(trace_ok, trace_fail):
    rows = align_steps(Session.load(trace_ok), Session.load(trace_fail))
    kinds = [r.kind for r in rows]
    assert kinds == ["status_changed", "added", "same"]


def test_reordered_steps_surface_as_delete_plus_insert_not_moves(tmp_path):
    from redbg import Recorder

    p1 = str(tmp_path / "a.jsonl")
    p2 = str(tmp_path / "b.jsonl")
    with Recorder(p1) as rec:
        for tool in ("t1", "t2"):
            c = rec.tool_call(tool, {})
            rec.tool_result(c, ok=True, output="x")
    with Recorder(p2) as rec:
        for tool in ("t2", "t1"):
            c = rec.tool_call(tool, {})
            rec.tool_result(c, ok=True, output="x")
    rows = align_steps(Session.load(p1), Session.load(p2))
    kinds = {r.kind for r in rows}
    # Honest reporting: delete + insert, never a fabricated "moved".
    assert "added" in kinds and "removed" in kinds
    assert "moved" not in kinds


def test_diff_handles_different_lengths_without_crashing(tmp_path):
    from redbg import Recorder

    p1 = str(tmp_path / "a.jsonl")
    p2 = str(tmp_path / "b.jsonl")
    with Recorder(p1) as rec:
        for i in range(10):
            c = rec.tool_call(f"tool_{i}", {"i": i})
            rec.tool_result(c, ok=True, output="x")
    with Recorder(p2):
        pass  # zero steps
    report = render_diff(Session.load(p1), Session.load(p2), use_color=False)
    assert "A: 10 steps · B: 0 steps" in report
