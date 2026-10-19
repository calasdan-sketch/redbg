import gzip
import json
import os
import sys
import threading

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg import Recorder  # noqa: E402
from redbg.replay import load_events  # noqa: E402


def _events(path):
    return load_events(path)


def test_round_trip_records_all_event_types(tmp_path):
    path = str(tmp_path / "s.jsonl")
    with Recorder(path, agent="a1", meta={"k": "v"}) as rec:
        rec.prompt("user", "hello")
        rec.response("hi there", model="m")
        rec.note("a note")
        call = rec.tool_call("my_tool", {"x": 1})
        rec.tool_result(call, ok=True, output="out")
    types = [e["type"] for e in _events(path)]
    assert types == [
        "session_start",
        "prompt",
        "response",
        "note",
        "tool_call",
        "tool_result",
        "session_end",
    ]
    assert _events(path)[0]["agent"] == "a1"
    assert _events(path)[-1]["status"] == "ok"


def test_step_numbers_increment(tmp_path):
    path = str(tmp_path / "s.jsonl")
    with Recorder(path) as rec:
        c1 = rec.tool_call("t", {})
        rec.tool_result(c1, ok=True, output="1")
        c2 = rec.tool_call("t", {})
        rec.tool_result(c2, ok=True, output="2")
    calls = [e for e in _events(path) if e["type"] == "tool_call"]
    assert [c["step"] for c in calls] == [1, 2]
    results = [e for e in _events(path) if e["type"] == "tool_result"]
    assert [r["step"] for r in results] == [1, 2]


def test_tool_result_unknown_call_id_raises(tmp_path):
    path = str(tmp_path / "s.jsonl")
    with Recorder(path) as rec:
        with pytest.raises(ValueError, match="unknown tool_call id"):
            rec.tool_result("nope", ok=True, output="x")


def test_output_truncation_keeps_sha_of_full_text(tmp_path):
    path = str(tmp_path / "s.jsonl")
    big = "x" * 5000
    with Recorder(path, max_output_chars=100) as rec:
        call = rec.tool_call("t", {})
        rec.tool_result(call, ok=True, output=big)
    result = [e for e in _events(path) if e["type"] == "tool_result"][0]
    assert "truncated" in result["output"]
    assert len(result["output"]) < 5000
    import hashlib

    assert result["output_sha256"] == hashlib.sha256(big.encode()).hexdigest()


def test_redaction_at_record_time(tmp_path):
    path = str(tmp_path / "s.jsonl")
    with Recorder(path) as rec:
        call = rec.tool_call("login", {"api_key": "sk-abc123XYZ789qwerty"})
        rec.tool_result(call, ok=True, output="token=ghp_1234567890abcdef1234")
    events = _events(path)
    call = next(e for e in events if e["type"] == "tool_call")
    assert call["args"]["api_key"] == "[REDACTED]"
    result = next(e for e in events if e["type"] == "tool_result")
    assert "ghp_" not in result["output"]
    assert rec.redactions >= 2


def test_redaction_can_be_disabled(tmp_path):
    path = str(tmp_path / "s.jsonl")
    with Recorder(path, redact=False) as rec:
        call = rec.tool_call("login", {"api_key": "secret-value"})
        rec.tool_result(call, ok=True, output="ok")
    call = next(e for e in _events(path) if e["type"] == "tool_call")
    assert call["args"]["api_key"] == "secret-value"


def test_wrap_decorator_records_success_and_failure(tmp_path):
    path = str(tmp_path / "s.jsonl")
    with Recorder(path) as rec:

        @rec.wrap
        def add(a, b):
            return a + b

        @rec.wrap(name="boom")
        def fails():
            raise RuntimeError("kaput")

        assert add(2, 3) == 5
        with pytest.raises(RuntimeError):
            fails()
    events = _events(path)
    results = [e for e in events if e["type"] == "tool_result"]
    assert len(results) == 2
    assert results[0]["ok"] is True and results[0]["tool"] == "add"
    assert results[1]["ok"] is False and "kaput" in results[1]["error"]
    assert results[1]["tool"] == "boom"


def test_gzip_output(tmp_path):
    path = str(tmp_path / "s.jsonl.gz")
    with Recorder(path) as rec:
        call = rec.tool_call("t", {})
        rec.tool_result(call, ok=True, output="x")
    with gzip.open(path, "rt") as handle:
        lines = handle.readlines()
    assert len(lines) == 4  # start, call, result, end
    assert len(load_events(path)) == 4  # transparent read-back


def test_exception_in_block_marks_session_error(tmp_path):
    path = str(tmp_path / "s.jsonl")
    with pytest.raises(RuntimeError):
        with Recorder(path) as rec:
            rec.prompt("user", "hi")
            raise RuntimeError("agent crashed")
    end = _events(path)[-1]
    assert end["type"] == "session_end"
    assert end["status"] == "error"
    assert "agent crashed" in end["error"]


def test_unserializable_args_coerced_not_crashed(tmp_path):
    path = str(tmp_path / "s.jsonl")

    class Weird:
        def __repr__(self):
            return "<Weird>"

    with Recorder(path) as rec:
        call = rec.tool_call("t", {"obj": Weird(), "fn": len})
        rec.tool_result(call, ok=True, output={"set": {1, 2}})
    call = next(e for e in _events(path) if e["type"] == "tool_call")
    assert call["args"]["obj"] == "<Weird>"
    # The file must be valid JSON throughout.
    with open(path) as handle:
        for line in handle:
            json.loads(line)


def test_thread_safe_recording(tmp_path):
    path = str(tmp_path / "s.jsonl")

    def worker(n):
        for _ in range(20):
            call = rec.tool_call("t", {"n": n})
            rec.tool_result(call, ok=True, output="x")

    with Recorder(path) as rec:
        threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
    calls = [e for e in _events(path) if e["type"] == "tool_call"]
    assert len(calls) == 80
    assert sorted(c["step"] for c in calls) == list(range(1, 81))


def test_huge_args_are_truncated_deep(tmp_path):
    path = str(tmp_path / "s.jsonl")
    big = "y" * 5000
    with Recorder(path, max_output_chars=100) as rec:
        call = rec.tool_call("t", {"blob": big, "nested": {"deep": big}})
        rec.tool_result(call, ok=True, output="x")
    call = next(e for e in _events(path) if e["type"] == "tool_call")
    assert len(call["args"]["blob"]) < 5000
    assert "truncated" in call["args"]["blob"]
    assert "truncated" in call["args"]["nested"]["deep"]
    # Small values are untouched.
    with Recorder(path, max_output_chars=100) as rec:
        call = rec.tool_call("t", {"small": "abc"})
        rec.tool_result(call, ok=True, output="x")
    call = next(e for e in _events(path) if e["type"] == "tool_call")
    assert call["args"]["small"] == "abc"


def test_huge_prompt_and_response_are_truncated(tmp_path):
    path = str(tmp_path / "s.jsonl")
    big = "z" * 5000
    with Recorder(path, max_output_chars=100) as rec:
        rec.prompt("user", big)
        rec.response(big)
    events = _events(path)
    prompt = next(e for e in events if e["type"] == "prompt")
    response = next(e for e in events if e["type"] == "response")
    assert "truncated" in prompt["text"]
    assert "truncated" in response["text"]
    assert len(prompt["text"]) < 5000


def test_truncation_disabled_with_negative_limit(tmp_path):
    path = str(tmp_path / "s.jsonl")
    big = "w" * 5000
    with Recorder(path, max_output_chars=-1) as rec:
        rec.prompt("user", big)
        call = rec.tool_call("t", {"blob": big})
        rec.tool_result(call, ok=True, output=big)
    events = _events(path)
    assert next(e for e in events if e["type"] == "prompt")["text"] == big
    call = next(e for e in events if e["type"] == "tool_call")
    assert call["args"]["blob"] == big
    result = next(e for e in events if e["type"] == "tool_result")
    assert result["output"] == big
