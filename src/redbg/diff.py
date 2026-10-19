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

from .replay import Session, Step

# Step classifications in the side-by-side table.
SAME = "same"
ARGS_CHANGED = "args_changed"
TOOL_CHANGED = "tool_changed"
STATUS_CHANGED = "status_changed"
ADDED = "added"
REMOVED = "removed"


def step_signature(step: Step) -> tuple[str, str]:
    args_json = json.dumps(step.args, sort_keys=True, default=str, ensure_ascii=False)
    return (step.tool, args_json)


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


def align_steps(a: Session, b: Session) -> list[AlignedRow]:
    sig_a = [step_signature(s) for s in a.steps]
    sig_b = [step_signature(s) for s in b.steps]
    matcher = difflib.SequenceMatcher(None, sig_a, sig_b, autojunk=False)
    rows: list[AlignedRow] = []
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
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


def _describe_args_change(a_step: Step, b_step: Step) -> str:
    a_args = json.dumps(a_step.args, sort_keys=True, indent=2, default=str)
    b_args = json.dumps(b_step.args, sort_keys=True, indent=2, default=str)
    diff = list(
        difflib.unified_diff(
            a_args.splitlines(),
            b_args.splitlines(),
            fromfile=f"A:{a_step.n} args",
            tofile=f"B:{b_step.n} args",
            lineterm="",
        )
    )
    changed_keys = sorted(
        set(a_step.args) ^ set(b_step.args)
        | {
            k
            for k in a_step.args
            if k in b_step.args and a_step.args[k] != b_step.args[k]
        }
    )
    detail = "\n".join(diff) if diff else "(no textual diff; ordering only)"
    return detail, changed_keys


def find_divergence(
    a: Session, b: Session, rows: list[AlignedRow] | None = None
) -> Divergence | None:
    """Return the first divergence, or None if the runs are identical."""
    rows = rows if rows is not None else align_steps(a, b)
    for row in rows:
        if row.kind == SAME:
            continue
        a_n = f"A:{row.a_n}" if row.a_n is not None else "A:—"
        b_n = f"B:{row.b_n}" if row.b_n is not None else "B:—"
        if row.kind == ARGS_CHANGED and row.a_step and row.b_step:
            detail, changed = _describe_args_change(row.a_step, row.b_step)
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


def _short_args(step: Step, width: int) -> str:
    args = json.dumps(step.args, sort_keys=True, default=str, ensure_ascii=False)
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
) -> str:
    """Render the full diff report: headline, table, field diff, summary."""
    rows = align_steps(a, b)
    div = find_divergence(a, b, rows)
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
        lines.append(_color("✗ " + div.headline, _BOLD + "\033[31m", use_color))
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
        note = label
        if row.kind in (SAME, ARGS_CHANGED, STATUS_CHANGED):
            result_note = _result_note(row.a_step, row.b_step)
            if result_note:
                note = f"{label + '; ' if label else ''}{result_note}"
            if row.kind == ARGS_CHANGED and row.a_step:
                note += f"  {_short_args(row.a_step, args_width)}"
        line = f"{a_n:>5}  {b_n:>5}  {mark}  {tool_cell:<28}  {note}"
        lines.append(_color(line, _COLORS[row.kind], use_color))

    # Field-level diff at the divergence, with a little context.
    if div is not None and div.detail:
        lines.append("")
        lines.append(_color("── args diff at divergence ──", _BOLD, use_color))
        lines.append(div.detail)

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
