from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "bench"))
import gen  # noqa: E402

from redbg import Session  # noqa: E402


def test_bench_generators_produce_loadable_deterministic_logs(tmp_path):
    a = gen.gen_claude_code(str(tmp_path / "a.jsonl"), 300_000)
    b = gen.gen_claude_code(str(tmp_path / "b.jsonl"), 300_000)
    assert a["steps"] == b["steps"] and a["bytes"] == b["bytes"]
    s = Session.load(str(tmp_path / "a.jsonl"))
    assert s.format == "claude-code" and len(s.steps) == a["steps"]
    n = gen.gen_native(str(tmp_path / "n.jsonl"), 300_000)
    assert len(Session.load(str(tmp_path / "n.jsonl")).steps) == n["steps"]
