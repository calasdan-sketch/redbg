"""Mutation fuzz: hostile variants of real-shaped logs must never crash a viewer."""

from __future__ import annotations

import json
import random

from logs import cc_session, codex_session, write_lines

from redbg import Session, effects, explain, file_ledger
from redbg.analysis import Breakpoint
from redbg.htmlexport import render_html


def _mutate(rng, value, depth=0):
    r = rng.random()
    if r < 0.08:
        return rng.choice([None, 0, -1, 1e999, "", [], {}, True, "\x1b[31m", "A" * 5000])
    if isinstance(value, dict) and depth < 6:
        out = {}
        for k, v in value.items():
            if rng.random() < 0.05:
                continue
            out[k] = _mutate(rng, v, depth + 1)
        return out
    if isinstance(value, list) and depth < 6:
        return [_mutate(rng, v, depth + 1) for v in value]
    return value


def _exercise(path):
    try:
        s = Session.load(path, skip_bad=True)
    except ValueError:
        return  # a clean, reported refusal is fine; a crash is not
    file_ledger(s)
    render_html(s)
    for step in s.steps:
        effects(step)
        explain(s, step.n)
        Breakpoint.parse("~tool").matches(step)
        Breakpoint.parse("file:*.py").matches(step)


def test_fuzz_claude_code_and_codex(tmp_path):
    rng = random.Random(1234)
    for base in (cc_session, codex_session):
        for i in range(60):
            objs = [_mutate(rng, o) for o in base()]
            rng.shuffle(objs) if i % 5 == 0 else None
            tail = None if i % 3 else json.dumps(objs[0])[: rng.randint(1, 40)]
            _exercise(write_lines(tmp_path / f"f{i}.jsonl", objs, tail=tail))
