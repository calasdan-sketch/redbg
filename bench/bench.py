"""Reproducible benchmark: parse speed, peak memory, time-to-first-view.

    python bench/bench.py                 # 100 MB, writes bench/RESULTS.md
    python bench/bench.py --mb 20         # quick run
    python bench/bench.py --baseline b7d5254   # also run an older git ref

Each measurement runs in a fresh subprocess so peak RSS is clean. Inputs
are generated deterministically by bench/gen.py (no real data). "Time to
first view" is wall-clock for ``redbg replay FILE --show 1`` including
interpreter start-up, i.e. what a user waits for before seeing step 1.
"""

from __future__ import annotations

import argparse
import io
import json
import os
import platform
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import gen  # noqa: E402

CHILD = r"""
import json, resource, sys, time
sys.path.insert(0, sys.argv[1])
from redbg import Session
t = time.perf_counter()
s = Session.load(sys.argv[2])
dt = time.perf_counter() - t
print(json.dumps({"load_s": dt, "steps": len(s.steps),
  "rss_mb": resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024}))
"""


def run_load(src_dir: str, path: str) -> dict | None:
    out = subprocess.run([sys.executable, "-c", CHILD, src_dir, path],
                         capture_output=True, text=True)
    if out.returncode != 0:
        return None
    return json.loads(out.stdout.strip().splitlines()[-1])


def run_cli(src_dir: str, argv: list[str]) -> float | None:
    env = dict(os.environ, PYTHONPATH=src_dir)
    t = time.perf_counter()
    r = subprocess.run([sys.executable, "-m", "redbg.cli", *argv],
                       capture_output=True, env=env)
    dt = time.perf_counter() - t
    return dt if r.returncode == 0 else None


def best(fn, n=3):
    vals = [v for v in (fn() for _ in range(n)) if v is not None]
    return min(vals) if vals else None


def fmt(v, unit="s", nd=2):
    return "cannot open" if v is None else f"{v:.{nd}f} {unit}"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--mb", type=int, default=100)
    ap.add_argument("--baseline", help="git ref of an older redbg to compare")
    ap.add_argument("--out", default=os.path.join(HERE, "RESULTS.md"))
    args = ap.parse_args()

    work = tempfile.mkdtemp(prefix="redbg-bench-")
    try:
        run(args, work)
    finally:
        shutil.rmtree(work, ignore_errors=True)  # the inputs are ~200 MB


def run(args, work) -> None:
    cc = os.path.join(work, "claude-code.jsonl")
    nat = os.path.join(work, "native.jsonl")
    ci = gen.gen_claude_code(cc, args.mb * 1024 * 1024)
    ni = gen.gen_native(nat, args.mb * 1024 * 1024)

    targets = {"current": os.path.join(ROOT, "src")}
    if args.baseline:
        base = os.path.join(work, "baseline")
        os.makedirs(base)
        archive = subprocess.run(
            ["git", "-C", ROOT, "archive", "--format=tar", args.baseline, "src"],
            check=True, capture_output=True,
        ).stdout
        with tarfile.open(fileobj=io.BytesIO(archive)) as tar:
            try:
                tar.extractall(base, filter="data")
            except TypeError:  # Python without extraction filters
                tar.extractall(base)  # noqa: S202 - our own repo's archive
        targets[args.baseline] = os.path.join(base, "src")

    rows = []
    for label, src in targets.items():
        for name, path, info in (("redbg native", nat, ni), ("Claude Code", cc, ci)):
            res = run_load(src, path)
            ttfv = best(lambda: run_cli(src, ["replay", path, "--show", "1"]))  # noqa: B023
            mid = str(info["steps"] // 2)
            why = best(lambda: run_cli(src, ["why", path, mid]), 1)  # noqa: B023
            # `audit` and `check` commands are newer than old baseline refs, which show "-".
            aud = best(lambda: run_cli(src, ["audit", path, "--no-color"]), 1)  # noqa: B023
            chk = best(  # noqa: B023
                lambda: run_cli(
                    src, ["check", path, "--baseline", path, "--max-cycles", "99"]  # noqa: B023
                ),
                1,
            )
            # `otel` and `digest` are new in round 5: older refs show "-".
            otl = best(lambda: run_cli(src, ["otel", path, "-o", os.devnull]), 1)  # noqa: B023
            dig = best(lambda: run_cli(src, ["digest", path]), 1)  # noqa: B023
            rows.append((label, name, info, res, ttfv, why, aud, chk, otl, dig))

    lines = [
        f"# Benchmark ({args.mb} MB inputs)",
        "",
        f"Python {platform.python_version()} on {platform.system()} {platform.machine()}; "
        "best of 3 for time-to-first-view, single run for load. Re-run: "
        "`python bench/bench.py`.",
        "",
        "Host load average (1/5/15 min) at the end of the run: "
        + (
            "/".join(f"{x:.1f}" for x in os.getloadavg())
            if hasattr(os, "getloadavg")
            else "n/a"
        )
        + ". Absolute times scale with it; compare rows within one table.",
        "",
        "| version | input | file MB | steps | full load | peak memory | time to first view | `why` (mid-step) | `audit` | `check` vs itself | `otel` | `digest` |",
        "|---|---|---|---|---|---|---|---|---|---|---|---|",
    ]
    for label, name, info, res, ttfv, why, aud, chk, otl, dig in rows:
        lines.append(
            f"| {label} | {name} | {info['bytes'] / 1e6:.0f} | {info['steps']} | "
            f"{fmt(res['load_s']) if res else 'cannot open'} | "
            f"{fmt(res['rss_mb'], 'MB', 0) if res else '-'} | {fmt(ttfv)} | "
            f"{fmt(why) if why is not None else '-'} | "
            f"{fmt(aud) if aud is not None else '-'} | "
            f"{fmt(chk) if chk is not None else '-'} | "
            f"{fmt(otl) if otl is not None else '-'} | "
            f"{fmt(dig) if dig is not None else '-'} |"
        )
    text = "\n".join(lines) + "\n"
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(text)
    print(text)


if __name__ == "__main__":
    main()
