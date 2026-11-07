from __future__ import annotations

import gzip
import json

import pytest
from logs import (
    cc_result,
    cc_session,
    cc_use,
    cc_user,
    codex_session,
    fake_key,
    write_lines,
)

from redbg import Session
from redbg.cli import main
from redbg.formats import CLAUDE_CODE, CODEX, MESSAGES, NATIVE, OTEL, sniff


def test_sniff_all_formats(tmp_path, trace_ok):
    assert sniff(trace_ok) == NATIVE
    assert sniff(write_lines(tmp_path / "c.jsonl", cc_session())) == CLAUDE_CODE
    assert sniff(write_lines(tmp_path / "x.jsonl", codex_session())) == CODEX
    arr = tmp_path / "m.json"
    arr.write_text(json.dumps([{"role": "user", "content": "hi"}]))
    assert sniff(str(arr)) == MESSAGES
    spans = tmp_path / "s.json"
    spans.write_text(json.dumps([{"name": "tool.echo", "attributes": {}}]))
    assert sniff(str(spans)) == OTEL
    empty = tmp_path / "e.jsonl"
    empty.write_text("")
    assert sniff(str(empty)) == NATIVE


def test_claude_code_pairs_steps_and_errors(tmp_path):
    s = Session.load(write_lines(tmp_path / "c.jsonl", cc_session()))
    assert s.format == CLAUDE_CODE and s.agent == "claude-code"
    assert [x.tool for x in s.steps] == ["Read", "Edit", "Bash"]
    assert [x.ok for x in s.steps] == [True, True, False]
    assert s.steps[2].error == "1 failed"
    assert s.steps[0].prompt_ctx["text"].startswith("Fix the bug")
    assert s.steps[0].response_ctx["text"] == "Reading it."
    assert s.steps[2].duration_ms == pytest.approx(4000, abs=1)
    assert s.status == "ok"


def test_claude_code_schema_drift_is_counted_not_fatal(tmp_path):
    objs = cc_session() + [
        {"type": "brand-new-thing", "sessionId": "S1", "x": 1},
        {"type": "assistant", "message": {"role": "assistant", "content": [
            {"type": "hologram", "data": 1}, {"type": "thinking", "thinking": "x"}]}},
        {"type": "assistant", "message": "not a dict"},
        [1, 2, 3],
        cc_result("ghost", "orphan result"),
    ]
    s = Session.load(write_lines(tmp_path / "c.jsonl", objs))
    assert len(s.steps) == 4  # the orphan result is surfaced, not dropped
    note = next(e["text"] for e in s.events if e["type"] == "note" and "ignored" in e["text"])
    assert "brand-new-thing=1" in note and "block:hologram=1" in note


def test_truncated_tail_is_reported_and_fails_check_closed(tmp_path):
    p = write_lines(tmp_path / "c.jsonl", cc_session(), tail='{"type": "assistant", "mess')
    s = Session.load(p)
    assert len(s.steps) == 3
    assert s.status == "truncated"
    assert any("cut off" in e.get("text", "") for e in s.events)
    assert main(["check", p, "--max-steps", "99"]) == 1


def test_deeply_nested_and_garbage_lines_do_not_crash(tmp_path):
    nest = "[" * 5000 + "]" * 5000
    p = write_lines(tmp_path / "c.jsonl", cc_session(), tail=nest + "\n\x00\x01garbage\n")
    s = Session.load(p)
    assert len(s.steps) == 3


def test_parallel_tool_use_in_one_message(tmp_path):
    msg = {"type": "assistant", "sessionId": "S1", "timestamp": "2026-01-01T00:00:01.000Z",
           "message": {"role": "assistant", "content": [
               {"type": "tool_use", "id": "a", "name": "Read", "input": {"file_path": "x"}},
               {"type": "tool_use", "id": "b", "name": "Read", "input": {"file_path": "y"}}]}}
    res = {"type": "user", "sessionId": "S1", "message": {"role": "user", "content": [
        {"type": "tool_result", "tool_use_id": "b", "content": "Y"},
        {"type": "tool_result", "tool_use_id": "a", "content": "X"}]}}
    s = Session.load(write_lines(tmp_path / "c.jsonl", [cc_user("go"), msg, res]))
    assert [(x.args["file_path"], x.output) for x in s.steps] == [("x", "X"), ("y", "Y")]


def test_sidechain_and_compaction(tmp_path):
    objs = [cc_user("go"),
            cc_use("a", "Task", {"p": 1}, isSidechain=True),
            {"type": "system", "subtype": "compact_boundary", "sessionId": "S1"},
            cc_user("summary text", isCompactSummary=True)]
    s = Session.load(write_lines(tmp_path / "c.jsonl", objs))
    assert s.steps[0].call.get("sidechain") is True
    texts = [e["text"] for e in s.events if e["type"] == "note"]
    assert any("compacted" in t for t in texts)
    assert len(s.prompts) == 1  # the compact summary is a note, not a user prompt


def test_big_output_is_cut_with_hash_and_memory_stays_bounded(tmp_path):
    big = "x" * 500_000
    objs = [cc_user("go"), cc_use("a", "Read", {"file_path": "f"}), cc_result("a", big)]
    s = Session.load(write_lines(tmp_path / "c.jsonl", objs))
    out = s.steps[0].output
    assert len(out) < 20_500 and "truncated" in out
    assert len(s.steps[0].output_sha256) == 64
    full = Session.load(write_lines(tmp_path / "c.jsonl", objs), max_output_chars=10**9)
    assert len(full.steps[0].output) == 500_000


def test_redact_happens_before_truncation_no_partial_pem(tmp_path):
    body = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASC" * 40
    pem = "-----BEGIN " + "PRIVATE KEY-----\n" + body + "\n-----END " + "PRIVATE KEY-----"
    out = "a" * 19_900 + "\n" + pem  # the PEM straddles the 20k cut
    objs = [cc_user("go"), cc_use("a", "Bash", {"command": "cat key"}), cc_result("a", out)]
    p = write_lines(tmp_path / "c.jsonl", objs)
    leaky = Session.load(p).steps[0].output
    assert "MIIEvQIBADANBg" in leaky  # default view keeps data: cut, no redaction
    safe = Session.load(p, redact=True).steps[0].output
    assert "MIIEvQIBADANBg" not in safe and "[REDACTED]" in safe


def test_secret_in_args_is_redacted_on_view(tmp_path):
    objs = [cc_user("go"), cc_use("a", "Bash", {"command": f"curl -H 'x-api-key: {fake_key()}'"}),
            cc_result("a", "ok")]
    p = write_lines(tmp_path / "c.jsonl", objs)
    assert fake_key() in json.dumps(Session.load(p).steps[0].args)
    assert fake_key() not in json.dumps(Session.load(p, redact=True).steps[0].args)


def test_codex_rollout(tmp_path):
    s = Session.load(write_lines(tmp_path / "r.jsonl", codex_session()))
    assert s.format == CODEX
    assert [x.tool for x in s.steps] == ["shell", "apply_patch"]
    assert s.steps[0].ok is False  # exit_code 2 inside the JSON output envelope
    assert s.steps[0].output == "a\nb"
    assert s.steps[1].ok is True
    assert s.session_id == "cx1"
    assert len(s.prompts) == 1 and len(s.responses) == 1


def test_messages_openai_and_anthropic_and_jsonl(tmp_path):
    openai = [
        {"role": "user", "content": "weather?"},
        {"role": "assistant", "content": None, "tool_calls": [
            {"id": "c1", "type": "function",
             "function": {"name": "get_weather", "arguments": '{"city": "Oslo"}'}}]},
        {"role": "tool", "tool_call_id": "c1", "content": "3C"},
        {"role": "assistant", "content": "cold"},
    ]
    p = tmp_path / "o.json"
    p.write_text(json.dumps({"messages": openai}))
    s = Session.load(str(p))
    assert s.format == MESSAGES
    assert s.steps[0].tool == "get_weather" and s.steps[0].args == {"city": "Oslo"}
    assert s.steps[0].output == "3C"
    anth = [
        {"role": "user", "content": "go"},
        {"role": "assistant", "content": [
            {"type": "tool_use", "id": "x", "name": "Read", "input": {"file_path": "a"}}]},
        {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "x", "content": "A"}]},
    ]
    q = write_lines(tmp_path / "a.jsonl", anth)
    s2 = Session.load(q)
    assert s2.steps[0].output == "A" and s2.format == MESSAGES


def test_gzip_foreign(tmp_path):
    p = tmp_path / "c.jsonl.gz"
    with gzip.open(p, "wt") as fh:
        for o in cc_session():
            fh.write(json.dumps(o) + "\n")
    assert len(Session.load(str(p)).steps) == 3


def test_native_files_unchanged_and_garbage_still_errors(tmp_path, trace_ok):
    assert Session.load(trace_ok).format == NATIVE
    bad = tmp_path / "bad.jsonl"
    bad.write_text("not json at all\n")
    with pytest.raises(ValueError):
        Session.load(str(bad))
    assert main(["info", str(bad)]) == 2


def test_partial_load_stops_early(tmp_path):
    p = write_lines(tmp_path / "c.jsonl", cc_session())
    s = Session.load(p, max_steps=1)
    assert s.partial and len(s.steps) == 1


def test_diff_and_check_work_across_foreign_logs(tmp_path):
    a = write_lines(tmp_path / "a.jsonl", cc_session())
    changed = cc_session()
    changed[4]["message"]["content"][0]["input"]["new_string"] = "3"
    b = write_lines(tmp_path / "b.jsonl", changed)
    assert main(["diff", a, b]) in (0, 1)
    assert main(["check", b, "--baseline", a]) == 1
    assert main(["check", a, "--baseline", a]) == 0


def test_import_converts_and_refuses_native_and_same_file(tmp_path, trace_ok, capsys):
    src = write_lines(tmp_path / "c.jsonl", cc_session())
    dst = str(tmp_path / "out.jsonl")
    assert main(["import", src, "-o", dst]) == 0
    assert Session.load(dst).format == NATIVE and len(Session.load(dst).steps) == 3
    assert main(["import", src, "-o", src]) == 2
    assert main(["import", trace_ok, "-o", str(tmp_path / "z.jsonl")]) == 2
    assert not (tmp_path / "out.jsonl.part").exists()


def test_import_redact_flag(tmp_path):
    objs = [cc_user("go"), cc_use("a", "Bash", {"command": f"echo {fake_key()}"}),
            cc_result("a", "ok")]
    src = write_lines(tmp_path / "c.jsonl", objs)
    dst = tmp_path / "o.jsonl"
    assert main(["import", src, "-o", str(dst), "--redact"]) == 0
    assert fake_key() not in dst.read_text()


def test_scan_and_redact_work_on_raw_foreign_logs(tmp_path):
    objs = [cc_user("go"), cc_use("a", "Bash", {"command": f"echo {fake_key()}"}),
            cc_result("a", "ok")]
    src = write_lines(tmp_path / "c.jsonl", objs)
    assert main(["scan", src]) == 1
    dst = tmp_path / "clean.jsonl"
    assert main(["redact", src, "-o", str(dst)]) == 0
    assert main(["scan", str(dst)]) == 0


def test_sniff_survives_giant_first_line_and_bom(tmp_path):
    huge = cc_user("x" * 6_000_000)
    p = write_lines(tmp_path / "c.jsonl", [huge, *cc_session()])
    assert sniff(p) == CLAUDE_CODE
    s = Session.load(p)
    assert len(s.steps) == 3 and len(s.prompts) == 2
    bom = tmp_path / "b.jsonl"
    bom.write_text("﻿" + json.dumps(cc_session()[1]) + "\n", encoding="utf-8")
    assert sniff(str(bom)) == CLAUDE_CODE


def test_pretty_printed_openai_document_and_split_multibyte_tail(tmp_path):
    doc = tmp_path / "p.json"
    doc.write_text(json.dumps({"messages": [{"role": "user", "content": "hi"}]}, indent=2))
    assert sniff(str(doc)) == MESSAGES and len(Session.load(str(doc)).prompts) == 1
    raw = tmp_path / "t.jsonl"
    body = "\n".join(json.dumps(o) for o in cc_session()) + "\n"
    raw.write_bytes(body.encode() + b'{"type":"user","message":{"content":"caf' + "é".encode()[:1])
    s = Session.load(str(raw))
    assert len(s.steps) == 3 and s.status == "truncated"
