"""Demo: a tiny fake agent loop recorded with redbg.

Produces two traces of the same task ("summarize main.py"):
- sample-a.jsonl: the clean run.
- sample-b.jsonl: the run where the first read fails (wrong path), the
  agent retries with the right path, and everything downstream shifts.

Run:  python examples/demo_agent.py
Then: redbg diff examples/sample-a.jsonl examples/sample-b.jsonl
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg import Recorder  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))

FILES = {
    "main.py": 'def main():\n    print("hello")\n',
    "README.md": "# demo\n",
}


def read_file(path: str) -> str:
    if path not in FILES:
        raise FileNotFoundError(f"no such file: {path}")
    return FILES[path]


def run(trace_path: str, first_path: str) -> None:
    with Recorder(
        trace_path, agent="demo-agent", meta={"task": "summarize main.py"}
    ) as rec:
        rec.prompt("user", "Summarize what main.py does.")
        rec.response("I'll read main.py first.", model="demo-1.0")

        call = rec.tool_call("read_file", {"path": first_path})
        try:
            content = read_file(first_path)
        except FileNotFoundError as exc:
            rec.tool_result(call, ok=False, error=str(exc))
            rec.response(
                "Wrong path — retrying with the correct one.", model="demo-1.0"
            )
            call = rec.tool_call("read_file", {"path": "main.py"})
            content = read_file("main.py")
            rec.tool_result(call, ok=True, output=content)
        else:
            rec.tool_result(call, ok=True, output=content)

        rec.response("main.py defines main(), which prints 'hello'.", model="demo-1.0")
        call = rec.tool_call(
            "write_file", {"path": "summary.txt", "content": "main.py prints hello\n"}
        )
        rec.tool_result(call, ok=True, output="wrote 19 bytes")


if __name__ == "__main__":
    run(os.path.join(HERE, "sample-a.jsonl"), "main.py")
    run(os.path.join(HERE, "sample-b.jsonl"), "wrong.py")
    print("wrote sample-a.jsonl and sample-b.jsonl")
