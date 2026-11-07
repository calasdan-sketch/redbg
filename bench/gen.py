"""Deterministic synthetic transcript generators for the benchmark.

Content is pseudo-random prose and file listings (no credentials, no real
paths). Sizes follow what agent transcripts look like: many small tool
results, a long tail of 5-60 KB ones (file reads, test logs), plus noise
lines (attachments, queue operations, thinking blocks) that a viewer must
skip.
"""

from __future__ import annotations

import json
import random
import sys
import uuid
from datetime import datetime, timedelta, timezone

WORDS = (
    "alpha beta gamma delta parse render tool agent result error value path "
    "config module import return class method buffer stream token window "
    "session replay query index cache write read open close retry timeout "
    "build test lint deploy commit branch merge diff patch hunk line file"
).split()


def _text(rng: random.Random, n: int) -> str:
    out, size = [], 0
    while size < n:
        w = rng.choice(WORDS)
        out.append(w)
        size += len(w) + 1
        if rng.random() < 0.08:
            out.append("\n")
    return " ".join(out)[:n]


def _size(rng: random.Random) -> int:
    r = rng.random()
    if r < 0.70:
        return rng.randint(80, 600)
    if r < 0.95:
        return rng.randint(2_000, 12_000)
    return rng.randint(20_000, 60_000)


TOOLS = ["Read", "Bash", "Edit", "Write", "Grep", "Glob"]


def _tool_input(rng, tool, i):
    path = f"/work/proj/src/mod_{rng.randint(1, 60)}.py"
    if tool == "Bash":
        return {"command": f"pytest -q tests/test_{rng.randint(1, 40)}.py"}
    if tool == "Edit":
        return {"file_path": path, "old_string": "alpha", "new_string": f"beta{i}"}
    if tool == "Write":
        return {"file_path": path, "content": _text(rng, rng.randint(100, 2000))}
    if tool == "Grep":
        return {"pattern": rng.choice(WORDS), "path": "/work/proj"}
    if tool == "Glob":
        return {"pattern": "**/*.py"}
    return {"file_path": path}


def gen_claude_code(path: str, target_bytes: int, seed: int = 7) -> dict:
    """Write a Claude Code-shaped JSONL transcript of ~target_bytes."""
    rng = random.Random(seed)
    sid = str(uuid.UUID(int=rng.getrandbits(128)))
    t = datetime(2026, 1, 1, tzinfo=timezone.utc)
    size = steps = 0
    parent = None

    def ts():
        return t.strftime("%Y-%m-%dT%H:%M:%S.") + f"{t.microsecond // 1000:03d}Z"

    with open(path, "w", encoding="utf-8") as fh:
        def emit(obj):
            nonlocal size
            line = json.dumps(obj, ensure_ascii=False)
            fh.write(line + "\n")
            size += len(line) + 1

        base = {"sessionId": sid, "version": "2.0.0", "cwd": "/work/proj",
                "isSidechain": False}
        emit({"type": "queue-operation", "operation": "enqueue", "timestamp": ts(),
              "sessionId": sid})
        while size < target_bytes:
            t += timedelta(seconds=rng.uniform(0.5, 30))
            if steps % 25 == 0:
                u = str(uuid.UUID(int=rng.getrandbits(128)))
                emit({**base, "type": "user", "uuid": u, "parentUuid": parent,
                      "timestamp": ts(),
                      "message": {"role": "user",
                                  "content": f"Task {steps}: " + _text(rng, 200)}})
                parent = u
            tool = rng.choice(TOOLS)
            tid = "toolu_" + uuid.UUID(int=rng.getrandbits(128)).hex[:22]
            if rng.random() < 0.3:
                emit({**base, "type": "assistant", "uuid": str(uuid.uuid4()),
                      "parentUuid": parent, "timestamp": ts(),
                      "message": {"role": "assistant", "id": "msg_x",
                                  "model": "model-x",
                                  "content": [{"type": "thinking", "thinking": "",
                                               "signature": _text(rng, 400)}]}})
            au = str(uuid.UUID(int=rng.getrandbits(128)))
            emit({**base, "type": "assistant", "uuid": au, "parentUuid": parent,
                  "timestamp": ts(),
                  "message": {"role": "assistant", "id": "msg_x", "model": "model-x",
                              "content": [{"type": "text", "text": _text(rng, 120)},
                                          {"type": "tool_use", "id": tid,
                                           "name": tool,
                                           "input": _tool_input(rng, tool, steps)}]}})
            t += timedelta(seconds=rng.uniform(0.05, 5))
            fail = rng.random() < 0.04
            ru = str(uuid.UUID(int=rng.getrandbits(128)))
            emit({**base, "type": "user", "uuid": ru, "parentUuid": au,
                  "timestamp": ts(),
                  "message": {"role": "user", "content": [
                      {"type": "tool_result", "tool_use_id": tid,
                       "content": _text(rng, _size(rng)), "is_error": fail}]}})
            parent = ru
            if rng.random() < 0.4:
                emit({"type": "attachment", "uuid": str(uuid.uuid4()),
                      "parentUuid": parent, "timestamp": ts(), "sessionId": sid,
                      "attachment": {"type": "file", "content": _text(rng, 3000)}})
            steps += 1
    return {"path": path, "bytes": size, "steps": steps}


def gen_native(path: str, target_bytes: int, seed: int = 7) -> dict:
    """Write a redbg-native JSONL trace of ~target_bytes."""
    rng = random.Random(seed)
    mono = 0.0
    size = steps = 0
    with open(path, "w", encoding="utf-8") as fh:
        def emit(ev):
            nonlocal size
            line = json.dumps(ev, ensure_ascii=False)
            fh.write(line + "\n")
            size += len(line) + 1

        def ev(kind, **f):
            nonlocal mono
            mono += 0.01
            return {"v": 1, "id": uuid.UUID(int=rng.getrandbits(128)).hex,
                    "ts": "2026-01-01T00:00:00.000+00:00", "mono": mono,
                    "type": kind, **f}

        emit(ev("session_start", agent="bench"))
        while size < target_bytes:
            if steps % 25 == 0:
                emit(ev("prompt", role="user", text=_text(rng, 200)))
            emit(ev("response", text=_text(rng, 120)))
            tool = rng.choice(TOOLS)
            call = ev("tool_call", step=steps + 1, tool=tool,
                      args=_tool_input(rng, tool, steps))
            emit(call)
            emit(ev("tool_result", step=steps + 1, call_id=call["id"], tool=tool,
                    ok=rng.random() > 0.04, output=_text(rng, min(_size(rng), 20000))))
            steps += 1
        emit(ev("session_end", status="ok"))
    return {"path": path, "bytes": size, "steps": steps}


if __name__ == "__main__":
    kind, out, mb = sys.argv[1], sys.argv[2], int(sys.argv[3])
    gen = {"claude-code": gen_claude_code, "native": gen_native}[kind]
    print(json.dumps(gen(out, mb * 1024 * 1024)))
