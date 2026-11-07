"""Builders for foreign-format logs. Fake secrets are assembled at runtime."""

from __future__ import annotations

import json


def fake_key() -> str:
    # assembled at runtime so no contiguous secret-shaped literal is committed
    return "sk-" + "ant-" + "api03-" + "Zq9" * 12


def write_lines(path, objs, tail=None):
    with open(path, "w", encoding="utf-8") as fh:
        for o in objs:
            fh.write(json.dumps(o) + "\n")
        if tail is not None:
            fh.write(tail)
    return str(path)


def cc_user(text, ts="2026-01-01T00:00:00.000Z", **kw):
    return {"type": "user", "uuid": "u" + str(abs(hash(text)) % 10**6), "sessionId": "S1",
            "timestamp": ts, "message": {"role": "user", "content": text}, **kw}


def cc_use(tid, name, inp, ts="2026-01-01T00:00:01.000Z", text=None, **kw):
    content = []
    if text:
        content.append({"type": "text", "text": text})
    content.append({"type": "tool_use", "id": tid, "name": name, "input": inp})
    return {"type": "assistant", "uuid": "a" + tid, "sessionId": "S1", "timestamp": ts,
            "message": {"role": "assistant", "model": "m-1", "content": content}, **kw}


def cc_result(tid, content, err=False, ts="2026-01-01T00:00:02.000Z"):
    return {"type": "user", "uuid": "r" + tid, "sessionId": "S1", "timestamp": ts,
            "message": {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": tid, "content": content,
                 "is_error": err}]}}


def cc_session():
    return [
        {"type": "queue-operation", "operation": "enqueue", "sessionId": "S1"},
        cc_user("Fix the bug in /work/app/main.py"),
        cc_use("t1", "Read", {"file_path": "/work/app/main.py"}, text="Reading it."),
        cc_result("t1", "def f(): return 1"),
        cc_use("t2", "Edit", {"file_path": "/work/app/main.py", "old_string": "1",
                              "new_string": "2"}, ts="2026-01-01T00:00:03.000Z"),
        cc_result("t2", "edited", ts="2026-01-01T00:00:04.000Z"),
        cc_use("t3", "Bash", {"command": "pytest -q > /work/app/out.txt"},
               ts="2026-01-01T00:00:05.000Z"),
        cc_result("t3", [{"type": "text", "text": "1 failed"}], err=True,
                  ts="2026-01-01T00:00:09.000Z"),
    ]


def codex_session():
    def item(ts, payload):
        return {"timestamp": ts, "type": "response_item", "payload": payload}

    return [
        {"timestamp": "2026-01-01T00:00:00.000Z", "type": "session_meta",
         "payload": {"id": "cx1", "cwd": "/work", "cli_version": "0.1"}},
        item("2026-01-01T00:00:01.000Z", {"type": "message", "role": "user",
             "content": [{"type": "input_text", "text": "list files"}]}),
        item("2026-01-01T00:00:02.000Z", {"type": "reasoning", "summary": []}),
        item("2026-01-01T00:00:03.000Z", {"type": "function_call", "name": "shell",
             "arguments": json.dumps({"command": ["bash", "-lc", "ls > files.txt"]}),
             "call_id": "c1"}),
        item("2026-01-01T00:00:04.000Z", {"type": "function_call_output", "call_id": "c1",
             "output": json.dumps({"output": "a\nb", "metadata": {"exit_code": 2}})}),
        item("2026-01-01T00:00:05.000Z", {"type": "function_call", "name": "apply_patch",
             "arguments": json.dumps({"input": "*** Begin Patch\n*** Update File: src/a.py\n"
                                      "*** Add File: src/b.py\n*** Delete File: old.py\n"
                                      "*** End Patch"}), "call_id": "c2"}),
        item("2026-01-01T00:00:06.000Z", {"type": "function_call_output", "call_id": "c2",
             "output": "Done!"}),
        {"timestamp": "2026-01-01T00:00:06.500Z", "type": "event_msg",
         "payload": {"type": "agent_message", "message": "dup"}},
        item("2026-01-01T00:00:07.000Z", {"type": "message", "role": "assistant",
             "content": [{"type": "output_text", "text": "done"}]}),
    ]
