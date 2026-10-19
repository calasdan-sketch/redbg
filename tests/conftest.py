"""Shared fixtures for the redbg test suite."""

from __future__ import annotations

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg import Recorder  # noqa: E402


def record_session(path, agent="test-agent", fail_first=False):
    """Record a small deterministic session; returns the path."""
    with Recorder(path, agent=agent) as rec:
        rec.prompt("user", "do the thing")
        rec.response("on it", model="test-model")
        call = rec.tool_call("read_file", {"path": "a.txt"})
        if fail_first:
            rec.tool_result(call, ok=False, error="not found")
            call = rec.tool_call("read_file", {"path": "b.txt"})
            rec.tool_result(call, ok=True, output="contents of b")
        else:
            rec.tool_result(call, ok=True, output="contents of a")
        call = rec.tool_call("write_file", {"path": "out.txt", "content": "done"})
        rec.tool_result(call, ok=True, output="wrote 4 bytes")
    return path


@pytest.fixture()
def trace_ok(tmp_path):
    return record_session(str(tmp_path / "ok.jsonl"))


@pytest.fixture()
def trace_fail(tmp_path):
    return record_session(str(tmp_path / "fail.jsonl"), fail_first=True)


@pytest.fixture()
def trace_gz(tmp_path):
    return record_session(str(tmp_path / "ok.jsonl.gz"))
