"""Session diff: align two step streams and report where they diverge.

The algorithm is sequence alignment, not line diff:
1. Each step is normalized to a signature ``(tool, canonical_json(args))``.
2. ``difflib.SequenceMatcher`` (LCS) aligns the two signature streams.
3. The first non-equal opcode is the *divergence point* — the headline.
4. A side-by-side table classifies every step, and a field-level diff is
   shown at the divergence.

Deliberately, no "move detection": with repeated identical tool calls,
claiming a step *moved* is guesswork. Reordered steps surface honestly
as deletions + insertions.
"""

from __future__ import annotations

import difflib
import json
from dataclasses import dataclass

from ._text import clean
from .replay import Session, Step
from .schema import MAX_NESTING, TOO_DEEP

# Step classifications in the side-by-side table.
SAME = "same"
ARGS_CHANGED = "args_changed"
TOOL_CHANGED = "tool_changed"
STATUS_CHANGED = "status_changed"
ADDED = "added"
REMOVED = "removed"
# Not an alignment kind: a SAME/STATUS_CHANGED row whose recorded outputs
# differ. Only used by ``redbg check --fail-on output_changed``.
OUTPUT_CHANGED = "output_changed"

ALL_KINDS = (SAME, ARGS_CHANGED, TOOL_CHANGED, STATUS_CHANGED, ADDED, REMOVED)
CHANGE_KINDS = (ARGS_CHANGED, TOOL_CHANGED, STATUS_CHANGED, ADDED, REMOVED)

# Recursion guard for pathological (very deeply nested) args. Anything
# deeper is replaced by a constant marker — never ``repr`` it, which would
# itself recurse through the remaining levels.
_MAX_DEPTH = MAX_NESTING


def normalize_args(args, ignore_keys=frozenset(), _depth: int = 0):
    """Canonicalize args for comparison.

    - keys named in ``ignore_keys`` are dropped at any depth (use for
      request ids, timestamps, nonces that differ on every run);
    - integral floats compare equal to ints (``1.0`` == ``1``), matching
      JSON's single number type. Booleans are never coerced.
    """
    if _depth > _MAX_DEPTH:
        return TOO_DEEP
    if isinstance(args, dict):
        return {
            str(k): normalize_args(v, ignore_keys, _depth + 1)
            for k, v in args.items()
            if str(k) not in ignore_keys
        }
    if isinstance(args, (list, tuple)):
        return [normalize_args(v, ignore_keys, _depth + 1) for v in args]
    if isinstance(args, float) and args.is_integer():
        return int(args)
    return args


def _canonical(args, ignore_keys=frozenset(), indent=None) -> str:
    return json.dumps(
        normalize_args(args, ignore_keys),
        sort_keys=True,
        default=str,
        ensure_ascii=False,
        indent=indent,
    )


def step_signature(step: Step, ignore_keys=frozenset()) -> tuple[str, str]:
    return (step.tool, _canonical(step.args, frozenset(ignore_keys)))


@dataclass
class AlignedRow:
    a_n: int | None  # step number in session A (None = gap)
    b_n: int | None  # step number in session B (None = gap)
    kind: str  # one of SAME/ARGS_CHANGED/TOOL_CHANGED/ADDED/REMOVED
    a_step: Step | None = None
    b_step: Step | None = None


@dataclass
class Divergence:
    a_n: int | None
    b_n: int | None
    kind: str
    headline: str
    detail: str = ""


def align_steps(a: Session, b: Session, ignore_keys=()) -> list[AlignedRow]:
    ignore = frozenset(ignore_keys)
    sig_a = [step_signature(s, ignore) for s in a.steps]
    sig_b = [step_signature(s, ignore) for s in b.steps]
    # Runs usually start and end identically (that's the CI case: today vs the
    # golden run). Align only the differing middle: SequenceMatcher is
    # super-linear on long sequences of repeated calls, and two identical
    # 25,000-step runs took half a minute without this.
    na, nb = len(sig_a), len(sig_b)
    head = 0
    while head < na and head < nb and sig_a[head] == sig_b[head]:
        head += 1
    tail = 0
    while tail < na - head and tail < nb - head and sig_a[na - 1 - tail] == sig_b[nb - 1 - tail]:
        tail += 1
    ops: list[tuple[str, int, int, int, int]] = []
    if head:
        ops.append(("equal", 0, head, 0, head))
    if head < na - tail or head < nb - tail:
        matcher = difflib.SequenceMatcher(
            None, sig_a[head : na - tail], sig_b[head : nb - tail], autojunk=False
        )
        for tag, i1, i2, j1, j2 in matcher.get_opcodes():
            ops.append((tag, i1 + head, i2 + head, j1 + head, j2 + head))
    if tail:
        ops.append(("equal", na - tail, na, nb - tail, nb))
    rows: list[AlignedRow] = []
    for tag, i1, i2, j1, j2 in ops:
        if tag == "equal":
            for i, j in zip(range(i1, i2), range(j1, j2)):
                sa, sb = a.steps[i], b.steps[j]
                # Same tool, same args — but a different outcome is still a
                # divergence worth headlining (the classic "it worked Monday"
                # case), so it gets its own classification.
                kind = SAME if sa.ok == sb.ok else STATUS_CHANGED
                rows.append(AlignedRow(sa.n, sb.n, kind, sa, sb))
        elif tag == "replace":
            # Pair up 1:1 where possible so "args changed" reads naturally;
            # the leftovers become removed/added.
            pairs = min(i2 - i1, j2 - j1)
            for k in range(pairs):
                sa, sb = a.steps[i1 + k], b.steps[j1 + k]
                if sa.tool == sb.tool:
                    kind = ARGS_CHANGED
                else:
                    kind = TOOL_CHANGED
                rows.append(AlignedRow(sa.n, sb.n, kind, sa, sb))
            for i in range(i1 + pairs, i2):
                rows.append(AlignedRow(a.steps[i].n, None, REMOVED, a.steps[i], None))
            for j in range(j1 + pairs, j2):
                rows.append(AlignedRow(None, b.steps[j].n, ADDED, None, b.steps[j]))
        elif tag == "delete":
            for i in range(i1, i2):
                rows.append(AlignedRow(a.steps[i].n, None, REMOVED, a.steps[i], None))
        elif tag == "insert":
            for j in range(j1, j2):
                rows.append(AlignedRow(None, b.steps[j].n, ADDED, None, b.steps[j]))
    return rows


def _describe_args_change(
    a_step: Step, b_step: Step, ignore_keys=frozenset()
) -> tuple[str, list[str]]:
    a_norm = normalize_args(a_step.args, ignore_keys)
    b_norm = normalize_args(b_step.args, ignore_keys)
    a_args = _canonical(a_step.args, ignore_keys, indent=2)
    b_args = _canonical(b_step.args, ignore_keys, indent=2)
    diff = list(
        difflib.unified_diff(
            a_args.splitlines(),
            b_args.splitlines(),
            fromfile=f"A:{a_step.n} args",
            tofile=f"B:{b_step.n} args",
            lineterm="",
        )
    )
    if isinstance(a_norm, dict) and isinstance(b_norm, dict):
        changed_keys = sorted(
            set(a_norm) ^ set(b_norm)
            | {k for k in a_norm if k in b_norm and a_norm[k] != b_norm[k]}
        )
    else:  # args recorded as a non-object (list/scalar): no key names
        changed_keys = []
    detail = "\n".join(diff) if diff else "(no textual diff; ordering only)"
    return detail, changed_keys


def find_divergence(
    a: Session, b: Session, rows: list[AlignedRow] | None = None, ignore_keys=()
) -> Divergence | None:
    """Return the first divergence, or None if the runs are identical."""
    ignore = frozenset(ignore_keys)
    rows = rows if rows is not None else align_steps(a, b, ignore)
    for row in rows:
        if row.kind == SAME:
            continue
        a_n = f"A:{row.a_n}" if row.a_n is not None else "A:—"
        b_n = f"B:{row.b_n}" if row.b_n is not None else "B:—"
        if row.kind == ARGS_CHANGED and row.a_step and row.b_step:
            detail, changed = _describe_args_change(row.a_step, row.b_step, ignore)
            keys = ", ".join(changed) if changed else "args"
            return Divergence(
                row.a_n,
                row.b_n,
                ARGS_CHANGED,
                f"First divergence at {a_n} / {b_n}: "
                f"same tool {row.a_step.tool!r}, args changed ({keys})",
                detail,
            )
        if row.kind == TOOL_CHANGED and row.a_step and row.b_step:
            return Divergence(
                row.a_n,
                row.b_n,
                TOOL_CHANGED,
                f"First divergence at {a_n} / {b_n}: "
                f"tool changed {row.a_step.tool!r} → {row.b_step.tool!r}",
            )
        if row.kind == STATUS_CHANGED and row.a_step and row.b_step:
            a_s = _ok_word(row.a_step.ok)
            b_s = _ok_word(row.b_step.ok)
            return Divergence(
                row.a_n,
                row.b_n,
                STATUS_CHANGED,
                f"First divergence at {a_n} / {b_n}: "
                f"same tool {row.a_step.tool!r} with same args, "
                f"but A {a_s} and B {b_s}",
            )
        if row.kind == REMOVED and row.a_step:
            return Divergence(
                row.a_n,
                row.b_n,
                REMOVED,
                f"First divergence at {a_n} / {b_n}: "
                f"step removed in B ({row.a_step.tool!r})",
            )
        if row.kind == ADDED and row.b_step:
            return Divergence(
                row.a_n,
                row.b_n,
                ADDED,
                f"First divergence at {a_n} / {b_n}: "
                f"step added in B ({row.b_step.tool!r})",
            )
    return None


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

_KIND_MARK = {
    SAME: ("=", ""),
    ARGS_CHANGED: ("~", "args changed"),
    TOOL_CHANGED: ("!", "tool changed"),
    STATUS_CHANGED: ("≠", "status changed"),
    ADDED: ("+", "added in B"),
    REMOVED: ("-", "removed in B"),
}

_COLORS = {
    SAME: "",
    ARGS_CHANGED: "\033[33m",  # yellow
    TOOL_CHANGED: "\033[31m",  # red
    STATUS_CHANGED: "\033[33m",  # yellow
    ADDED: "\033[32m",  # green
    REMOVED: "\033[31m",  # red
}
_RESET = "\033[0m"
_BOLD = "\033[1m"


def _ok_word(ok: bool | None) -> str:
    if ok is True:
        return "succeeded"
    if ok is False:
        return "FAILED"
    return "has no result"


def _color(text: str, code: str, use_color: bool) -> str:
    if use_color and code:
        return f"{code}{text}{_RESET}"
    return text


def _short_args(step: Step, width: int, ignore_keys=frozenset()) -> str:
    args = _canonical(step.args, ignore_keys)
    if len(args) > width:
        args = args[: width - 1] + "…"
    return args


def _result_note(a_step: Step | None, b_step: Step | None) -> str:
    """Describe result similarity for an aligned row (output comparison)."""
    if a_step is None or b_step is None:
        return ""
    a_out, b_out = a_step.output_sha256, b_step.output_sha256
    if a_out and b_out:
        return "output same" if a_out == b_out else "output DIFFERS"
    a, b = a_step.output, b_step.output
    if a is None and b is None:
        return ""
    return "output same" if a == b else "output DIFFERS"


def render_diff(
    a: Session,
    b: Session,
    use_color: bool = True,
    context: int = 2,
    args_width: int = 44,
    ignore_keys=(),
) -> str:
    """Render the full diff report: headline, table, field diff, summary.

    All trace-derived text is passed through ``clean`` so a crafted trace
    can't inject terminal control sequences into the report.
    """
    ignore = frozenset(ignore_keys)
    rows = align_steps(a, b, ignore)
    div = find_divergence(a, b, rows, ignore)
    lines: list[str] = []

    # Headline.
    if div is None:
        lines.append(
            _color(
                f"✓ Sessions are identical: {len(a.steps)} steps, "
                "same tools, same args.",
                "\033[32m",
                use_color,
            )
        )
    else:
        lines.append(_color("✗ " + clean(div.headline), _BOLD + "\033[31m", use_color))
    lines.append("")

    # Side-by-side table.
    header = f"{'A':>5}  {'B':>5}  {' ':1}  {'tool (A → B)':<28}  {'note'}"
    lines.append(_color(header, _BOLD, use_color))
    lines.append("─" * min(len(header) + 20, 100))
    for row in rows:
        mark, label = _KIND_MARK[row.kind]
        a_n = str(row.a_n) if row.a_n is not None else "—"
        b_n = str(row.b_n) if row.b_n is not None else "—"
        tool_cell = (
            row.a_step.tool if row.a_step else (row.b_step.tool if row.b_step else "?")
        )
        if row.kind == TOOL_CHANGED and row.a_step and row.b_step:
            tool_cell = f"{row.a_step.tool} → {row.b_step.tool}"
        tool_cell = clean(tool_cell)
        note = label
        if row.kind in (SAME, ARGS_CHANGED, STATUS_CHANGED):
            result_note = _result_note(row.a_step, row.b_step)
            if result_note:
                note = f"{label + '; ' if label else ''}{result_note}"
            if row.kind == ARGS_CHANGED and row.a_step:
                note += f"  {clean(_short_args(row.a_step, args_width, ignore))}"
        line = f"{a_n:>5}  {b_n:>5}  {mark}  {tool_cell:<28}  {note}"
        lines.append(_color(line, _COLORS[row.kind], use_color))

    # Field-level diff at the divergence, with a little context.
    if div is not None and div.detail:
        lines.append("")
        lines.append(_color("── args diff at divergence ──", _BOLD, use_color))
        lines.append(clean(div.detail))

    # Summary.
    counts = {k: 0 for k in _KIND_MARK}
    for row in rows:
        counts[row.kind] += 1
    lines.append("")
    summary = (
        f"A: {len(a.steps)} steps · B: {len(b.steps)} steps · "
        f"same {counts[SAME]}, args-changed {counts[ARGS_CHANGED]}, "
        f"tool-changed {counts[TOOL_CHANGED]}, "
        f"status-changed {counts[STATUS_CHANGED]}, "
        f"removed {counts[REMOVED]}, added {counts[ADDED]}"
    )
    lines.append(summary)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Machine-readable diff
# ---------------------------------------------------------------------------


def _step_brief(step: Step | None) -> dict | None:
    if step is None:
        return None
    return {
        "n": step.n,
        "tool": step.tool,
        "ok": step.ok,
        "output_sha256": step.output_sha256,
    }


def output_changed(row: AlignedRow) -> bool:
    """True when both sides have a result and the recorded outputs differ."""
    return _result_note(row.a_step, row.b_step) == "output DIFFERS"


def diff_to_dict(a: Session, b: Session, ignore_keys=()) -> dict:
    """The diff as plain data (what ``redbg diff --json`` prints).

    Stable keys: ``identical``, ``divergence``, ``counts``, ``rows``. Each
    row has ``kind``, ``a``/``b`` step briefs (or null for a gap), and
    ``output_changed``.
    """
    ignore = frozenset(ignore_keys)
    rows = align_steps(a, b, ignore)
    div = find_divergence(a, b, rows, ignore)
    counts = {k: 0 for k in ALL_KINDS}
    for row in rows:
        counts[row.kind] += 1
    return {
        "a": {"path": a.path, "steps": len(a.steps)},
        "b": {"path": b.path, "steps": len(b.steps)},
        "identical": div is None,
        "divergence": None
        if div is None
        else {
            "a_n": div.a_n,
            "b_n": div.b_n,
            "kind": div.kind,
            "headline": div.headline,
            "detail": div.detail,
        },
        "counts": counts,
        "rows": [
            {
                "kind": row.kind,
                "a": _step_brief(row.a_step),
                "b": _step_brief(row.b_step),
                "output_changed": output_changed(row),
            }
            for row in rows
        ],
    }


# ---------------------------------------------------------------------------
# Loop detection
# ---------------------------------------------------------------------------


@dataclass
class Repeat:
    """A run of consecutive steps with identical tool + args."""

    tool: str
    first: int
    last: int

    @property
    def count(self) -> int:
        return self.last - self.first + 1


def find_repeats(session: Session, min_count: int = 2, ignore_keys=()) -> list[Repeat]:
    """Find runs of >= ``min_count`` consecutive identical tool calls.

    An agent calling the same tool with the same args back-to-back is the
    most common shape of a stuck loop. Retries after a failure are also
    caught — which is usually what you want to see.
    """
    ignore = frozenset(ignore_keys)
    runs: list[Repeat] = []
    prev_sig = None
    start = None
    steps = session.steps
    for i, step in enumerate(steps):
        sig = step_signature(step, ignore)
        if sig != prev_sig:
            if start is not None and i - start >= min_count:
                runs.append(Repeat(steps[start].tool, steps[start].n, steps[i - 1].n))
            start = i
            prev_sig = sig
    if start is not None and len(steps) - start >= min_count:
        runs.append(Repeat(steps[start].tool, steps[start].n, steps[-1].n))
    return runs


@dataclass
class Cycle:
    """A short call pattern (period >= 2) that repeats back-to-back."""

    period: int
    tools: tuple[str, ...]
    first: int
    last: int
    reps: int


def find_cycles(
    session: Session,
    min_reps: int = 3,
    max_period: int = 8,
    ignore_keys=(),
) -> list[Cycle]:
    """Find alternating loops such as ``read, edit, read, edit, ...``.

    ``find_repeats`` only sees one call repeated back-to-back; stuck agents
    just as often flip between two or three calls. A cycle of ``period``
    calls (2..``max_period``) counts when the same signatures recur at least
    ``min_reps`` times in a row. Patterns made of a smaller repeat (``a a a
    a`` is a repeat, not a period-2 cycle) are left to ``find_repeats``.
    Calls are compared on tool + canonical args, so a counter in the args
    breaks a cycle: use ``ignore_keys`` for ids and timestamps.
    """
    ignore = frozenset(ignore_keys)
    sigs = [step_signature(s, ignore) for s in session.steps]
    n = len(sigs)
    covered = [False] * n
    found: list[Cycle] = []
    for period in range(2, max_period + 1):
        i = 0
        while i + period < n:
            if sigs[i] != sigs[i + period]:
                i += 1
                continue
            j = i
            while j + period < n and sigs[j] == sigs[j + period]:
                j += 1
            end = j + period - 1  # last step index covered by the pattern
            window = sigs[i : i + period]
            reps = (end - i + 1) // period
            smaller = any(
                period % q == 0 and window == window[:q] * (period // q)
                for q in range(1, period)
            )
            if reps >= min_reps and not smaller and not all(covered[i : end + 1]):
                for k in range(i, end + 1):
                    covered[k] = True
                found.append(
                    Cycle(
                        period,
                        tuple(s.tool for s in session.steps[i : i + period]),
                        session.steps[i].n,
                        session.steps[end].n,
                        reps,
                    )
                )
            i = j + 1
    return sorted(found, key=lambda c: c.first)
