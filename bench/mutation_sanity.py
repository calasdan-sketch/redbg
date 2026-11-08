"""Mutation-style sanity check: break one condition at a time, expect tests to fail.

Copies ``src`` and ``tests`` into a throw-away folder, applies each change in
turn, runs the test-suite, and reports any change the tests did NOT notice
("survivor"). Exit 1 if there is a survivor. Not part of the normal test run
(it starts the suite once per change).

    python bench/mutation_sanity.py [--scratch DIR]
"""

from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

# (file under src/redbg, text that must occur exactly once, replacement)
MUTATIONS = [
    ("redact.py", "if span[1] > span[0]:", "if span[1] >= span[0] + 99999:"),
    ("redact.py", "if not luhn_ok(match.group(\"card\")):", "if False:"),
    ("redact.py", "(?!\\[REDACTED\\])(?P<secret>[^/\\\\\\s\\\"'<>:|*?]{1,64})", "(?P<secret>[^/\\\\\\s\\\"'<>:|*?]{1,64})"),
    ("redact.py", "(?<![\\d.])(?:(?:25[0-5]", "(?:(?:25[0-5]"),
    ("redact.py", "or len(term.strip()) < 2", "or len(term.strip()) < 0"),
    ("check.py", "if value is not None and value < 0:", "if value is not None and value < -1:"),
    ("replay.py", "return raw if isinstance(raw, dict) else {\"_args\": raw}", "return raw"),
    ("replay.py", "call_id = hashable_id(event.get(\"call_id\"))", "call_id = event.get(\"call_id\")"),
    ("schema.py", "        hash(value)\n        return value", "        return value"),
    ("sarif.py", "\"organization\": AUTHOR,", "\"organization\": \"x\","),
    ("sarif.py", "\"level\": it[\"level\"]", "\"level\": \"note\""),
    ("sarif.py", "rel.replace(\"\\\\\", \"/\")", "rel"),
    ("otlp.py", "if end is None or end < start:", "if end is None:"),
    ("otlp.py", "if with_args:", "if True:"),
    ("otlp.py", "step.ok is False", "step.ok is True"),
    ("forensics.py", "if eid in ids:", "if False:"),
    ("forensics.py", "if prev is not None and ts < prev:", "if prev is not None and ts < prev - 1e12:"),
    ("cli.py", "mismatch = bool(args.expect) and args.expect.strip().lower() != sha",
     "mismatch = False"),
    ("cli.py", "if args.strict and any(f.severity == \"high\" for f in findings):",
     "if False:"),
    ("_fs.py", "if tmp != dst:", "if tmp == dst:"),
]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--scratch", help="work folder (default: a fresh temp folder)")
    args = ap.parse_args()
    base = args.scratch or tempfile.mkdtemp(prefix="redbg-mut-")
    survivors = []
    try:
        for i, (fname, old, new) in enumerate(MUTATIONS, start=1):
            work = os.path.join(base, f"m{i}")
            shutil.copytree(os.path.join(ROOT, "src"), os.path.join(work, "src"),
                            ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"))
            shutil.copytree(os.path.join(ROOT, "tests"), os.path.join(work, "tests"),
                            ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(os.path.join(ROOT, "examples"), os.path.join(work, "examples"))
            shutil.copy(os.path.join(ROOT, "pyproject.toml"), work)
            shutil.copy(os.path.join(ROOT, "LICENSE"), work)
            shutil.copy(os.path.join(ROOT, "README.md"), work)
            shutil.copy(os.path.join(ROOT, "CHANGELOG.md"), work)
            target = os.path.join(work, "src", "redbg", fname)
            text = open(target, encoding="utf-8").read()
            if text.count(old) != 1:
                print(f"[{i:2}] SKIP  {fname}: text not found exactly once: {old[:50]!r}")
                survivors.append((fname, old, "stale mutation"))
                continue
            open(target, "w", encoding="utf-8", newline="\n").write(text.replace(old, new))
            proc = subprocess.run(
                [sys.executable, "-m", "pytest", "-x", "-q", "-p", "no:cacheprovider",
                 "-o", "addopts=", "tests"],
                cwd=work, capture_output=True, text=True,
            )
            killed = proc.returncode != 0
            print(f"[{i:2}] {'killed ' if killed else 'SURVIVED'} {fname}: {old[:60]!r}")
            if not killed:
                survivors.append((fname, old, "survived"))
            shutil.rmtree(work, ignore_errors=True)
    finally:
        if not args.scratch:
            shutil.rmtree(base, ignore_errors=True)
    print(f"\n{len(MUTATIONS) - len(survivors)}/{len(MUTATIONS)} changes noticed by the tests")
    return 1 if survivors else 0


if __name__ == "__main__":
    sys.exit(main())
