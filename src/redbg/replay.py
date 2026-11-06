"""Replay engine: load a JSONL trace into steps and navigate them.

A *step* is one tool_call/tool_result pair — the atomic unit you step
through, gdb-style. Prompts and responses are kept as context around
steps, not as steps themselves.
"""

from __future__ import annotations

import gzip
import json
import os
from dataclasses import dataclass, field

from .schema import (
    NOTE,
    PROMPT,
    RESPONSE,
    SESSION_END,
    SESSION_START,
    TOOL_CALL,
    TOOL_RESULT,
    new_event,
    validate_event,
)


def open_trace(path: str):
    """Open a trace file for reading (transparent ``.gz`` support)."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", encoding="utf-8")
    return open(path, encoding="utf-8")


def ensure_distinct(src: str, dst: str) -> None:
    """Refuse to write ``dst`` when it is the same file as ``src``.

    Opening the output for writing truncates it before the input is read,
    so ``redbg redact t.jsonl -o t.jsonl`` would silently destroy the
    trace. Catches symlinks, hard links and differently-spelled paths.
    """
    same = False
    try:
        same = os.path.samefile(src, dst)
    except OSError:  # dst doesn't exist yet (the normal case), or src missing
        same = os.path.normcase(os.path.realpath(src)) == os.path.normcase(
            os.path.realpath(dst)
        )
    if same:
        raise ValueError(
            f"refusing to overwrite the input file {src!r}: "
            "write to a different output path"
        )


def load_events(path: str, skip_bad: bool = False) -> list[dict]:
    """Read every event from a JSONL trace.

    Raises ``ValueError`` naming the offending line on malformed JSON or
    invalid events, unless ``skip_bad`` is set (bad lines are then
    counted and ignored — use for salvaging crashed recordings).
    """
    events: list[dict] = []
    skipped = 0
    with open_trace(path) as handle:
        for line_no, line in enumerate(handle, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                event = json.loads(stripped)
            except (json.JSONDecodeError, RecursionError) as exc:
                if not skip_bad:
                    reason = (
                        "nested too deeply"
                        if isinstance(exc, RecursionError)
                        else f"malformed JSON: {exc}"
                    )
                    raise ValueError(f"{path}:{line_no}: {reason}") from None
                skipped += 1
                continue
            # Unknown event types are preserved (forward-compat) — the
            # step engine ignores them, it does not choke on them.
            problems = validate_event(event, allow_unknown_types=True)
            if problems:
                if not skip_bad:
                    raise ValueError(
                        f"{path}:{line_no}: invalid event: " + "; ".join(problems)
                    )
                skipped += 1
                continue
            events.append(event)
    if skipped:
        events.append(
            new_event(
                NOTE,
                text=f"[redbg] skipped {skipped} malformed line(s) while loading",
            )
        )
    return events


@dataclass
class Step:
    """One tool invocation: the call, its result, and nearby context."""

    n: int
    call: dict | None
    result: dict | None = None
    prompt_ctx: dict | None = None
    response_ctx: dict | None = None

    @property
    def tool(self) -> str:
        """Tool name, always a ``str`` (traces may hold ``123`` or ``null``)."""
        source = self.call or self.result or {}
        tool = source.get("tool")
        if tool is None:
            return "unknown"
        return tool if isinstance(tool, str) else str(tool)

    @property
    def args(self) -> dict:
        return (self.call or {}).get("args", {})

    @property
    def ok(self) -> bool | None:
        if self.result is None:
            return None
        return bool(self.result.get("ok"))

    @property
    def duration_ms(self) -> float | None:
        if not self.call or not self.result:
            return None
        try:
            return (self.result["mono"] - self.call["mono"]) * 1000.0
        except (KeyError, TypeError):
            return None

    @property
    def output(self) -> str | None:
        if self.result is None:
            return None
        return self.result.get("output")

    @property
    def output_sha256(self) -> str | None:
        if self.result is None:
            return None
        return self.result.get("output_sha256")

    @property
    def error(self) -> str | None:
        if self.result is None:
            return None
        return self.result.get("error")


@dataclass
class Session:
    """A loaded trace: steps plus session-level metadata."""

    path: str
    events: list[dict] = field(default_factory=list)
    steps: list[Step] = field(default_factory=list)
    agent: str = "unknown"
    session_id: str | None = None
    meta: dict = field(default_factory=dict)
    status: str | None = None

    @classmethod
    def load(cls, path: str, skip_bad: bool = False) -> Session:
        events = load_events(path, skip_bad=skip_bad)
        session = cls(path=path, events=events)
        session._index()
        return session

    def _index(self) -> None:
        steps: list[Step] = []
        by_call_id: dict[str, Step] = {}
        pending_results: dict[str, dict] = {}
        last_prompt: dict | None = None
        last_response: dict | None = None

        for event in self.events:
            etype = event.get("type")
            if etype == SESSION_START:
                self.agent = event.get("agent", "unknown")
                self.session_id = event.get("session_id")
                self.meta = event.get("meta", {})
            elif etype == SESSION_END:
                self.status = event.get("status")
            elif etype == PROMPT:
                last_prompt = event
            elif etype == RESPONSE:
                last_response = event
            elif etype == TOOL_CALL:
                step = Step(
                    n=len(steps) + 1,
                    call=event,
                    prompt_ctx=last_prompt,
                    response_ctx=last_response,
                )
                call_id = event.get("id")
                # A result may have arrived before its call (out-of-order
                # writers); attach it now if we buffered one.
                if call_id in pending_results:
                    step.result = pending_results.pop(call_id)
                by_call_id[call_id] = step
                steps.append(step)
            elif etype == TOOL_RESULT:
                call_id = event.get("call_id")
                step = by_call_id.get(call_id)
                if step is not None:
                    step.result = event
                else:
                    pending_results[call_id] = event
        # Orphan results (no matching call): surface them as steps with no
        # call so they are never silently dropped.
        for orphan in pending_results.values():
            steps.append(
                Step(
                    n=len(steps) + 1,
                    call=None,
                    result=orphan,
                    prompt_ctx=last_prompt,
                    response_ctx=last_response,
                )
            )
        # Numbering must be dense after orphans were appended.
        for i, step in enumerate(steps, start=1):
            step.n = i
        self.steps = steps

    def get_step(self, n: int) -> Step:
        if not 1 <= n <= len(self.steps):
            raise IndexError(
                f"step {n} out of range (session has {len(self.steps)} steps)"
            )
        return self.steps[n - 1]

    @property
    def prompts(self) -> list[dict]:
        return [e for e in self.events if e.get("type") == PROMPT]

    @property
    def responses(self) -> list[dict]:
        return [e for e in self.events if e.get("type") == RESPONSE]

    def search(self, pattern: str) -> list[int]:
        """Return step numbers whose tool/args/output mention ``pattern``."""
        needle = pattern.lower()
        hits: list[int] = []
        for step in self.steps:
            haystack = " ".join(
                str(part)
                for part in (
                    step.tool,
                    json.dumps(step.args, default=str),
                    step.output or "",
                    step.error or "",
                )
            ).lower()
            if needle in haystack:
                hits.append(step.n)
        return hits

    def timing_table(self) -> list[tuple[int, str, float | None, bool | None]]:
        return [(s.n, s.tool, s.duration_ms, s.ok) for s in self.steps]


class Navigator:
    """Cursor-based stepping over a session's steps (gdb-style)."""

    def __init__(self, session: Session):
        self.session = session
        self.cursor = 0  # 0 = before the first step; 1..N = at step N

    @property
    def count(self) -> int:
        return len(self.session.steps)

    def current(self) -> Step | None:
        if self.cursor == 0:
            return None
        return self.session.get_step(self.cursor)

    def next(self) -> Step | None:
        """Step forward one. Returns the step, or None at the end."""
        if self.cursor >= self.count:
            return None
        self.cursor += 1
        return self.session.get_step(self.cursor)

    def prev(self) -> Step | None:
        """Step back one. Returns the step, or None before the start."""
        if self.cursor <= 1:
            self.cursor = 0
            return None
        self.cursor -= 1
        return self.session.get_step(self.cursor)

    def goto(self, n: int) -> Step:
        self.session.get_step(n)  # validates range
        self.cursor = n
        return self.session.get_step(n)

    def reset(self) -> None:
        self.cursor = 0
