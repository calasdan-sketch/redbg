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
from typing import Any

from .schema import (
    NOTE,
    PROMPT,
    RESPONSE,
    SESSION_END,
    SESSION_START,
    TOOL_CALL,
    TOOL_RESULT,
    USAGE,
    new_event,
    validate_event,
)


def _sniff_encoding(path: str) -> tuple[bool, str]:
    """Return (is_gzip, text encoding) from the first bytes of ``path``.

    Windows PowerShell 5 writes ``> trace.jsonl`` as UTF-16 LE with a BOM
    and many Windows editors add a UTF-8 BOM; both must open. gzip is
    recognised by its magic number, so a misnamed or piped ``.gz`` works.
    """
    try:
        if not os.path.isfile(path):  # a pipe/FIFO: reading would consume bytes
            return path.endswith(".gz"), "utf-8"
        with open(path, "rb") as raw:
            head = raw.read(4)
    except OSError:
        return path.endswith(".gz"), "utf-8"
    if head[:2] == b"\x1f\x8b":
        return True, "utf-8"
    if head[:3] == b"\xef\xbb\xbf":
        return False, "utf-8-sig"
    if head[:4] in (b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff"):
        return False, "utf-32"
    if head[:2] in (b"\xff\xfe", b"\xfe\xff"):
        return False, "utf-16"
    return False, "utf-8"


def open_trace(path: str):
    """Open a trace file for reading (transparent gzip, UTF-8/16/32 BOMs)."""
    is_gz, encoding = _sniff_encoding(path)
    if is_gz or path.endswith(".gz"):
        # errors="replace": a log whose writer died mid-character must open.
        return gzip.open(path, "rt", encoding="utf-8-sig", errors="replace")
    return open(path, encoding=encoding, errors="replace")


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


def iter_native(path: str, skip_bad: bool = False):
    """Stream validated events from a native redbg JSONL trace.

    Raises ``ValueError`` naming the offending line on malformed JSON or
    invalid events, unless ``skip_bad`` is set (bad lines are then
    counted, ignored, and reported in a trailing note).
    """
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
            yield event
    if skipped:
        yield new_event(
            NOTE,
            text=f"[redbg] skipped {skipped} malformed line(s) while loading",
        )


def iter_any(
    path: str,
    skip_bad: bool = False,
    max_output_chars: int | None = None,
    redact: bool = False,
    fmt: str | None = None,
):
    """Stream events from any supported log (native or foreign), auto-detected."""
    from . import formats

    fmt = fmt or formats.sniff(path)
    if fmt == formats.NATIVE:
        if redact:
            from .redact import redact_event

            for event in iter_native(path, skip_bad):
                yield redact_event(event)[0]
        else:
            yield from iter_native(path, skip_bad)
        return
    yield from formats.iter_events(
        path,
        fmt,
        max_output_chars=(
            formats.DEFAULT_MAX_OUTPUT_CHARS if max_output_chars is None else max_output_chars
        ),
        redact=redact,
    )


def load_events(path: str, skip_bad: bool = False) -> list[dict]:
    """Read every event from a native JSONL trace (strict; see ``iter_native``)."""
    return list(iter_native(path, skip_bad))


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
    partial: bool = False
    format: str = ""
    usage: dict = field(default_factory=dict)
    """Summed token counts from ``usage`` events (empty if none recorded):
    ``input``, ``output``, ``cache_read``, ``cache_creation``, ``calls``."""

    @classmethod
    def load(
        cls,
        path: str,
        skip_bad: bool = False,
        *,
        max_steps: int | None = None,
        max_output_chars: int | None = None,
        redact: bool = False,
    ) -> Session:
        """Load a trace in any supported format (auto-detected).

        ``max_steps`` stops reading once that many tool results have been
        seen (``session.partial`` is then True): time-to-first-view stays
        flat no matter how big the file is. ``redact`` scrubs secrets
        from every event before it is indexed.
        """
        from . import formats

        fmt = formats.sniff(path)
        if fmt == formats.NATIVE and max_steps is None and not redact:
            # The common strict path keeps its exact historical behaviour.
            session = cls(path=path, events=load_events(path, skip_bad=skip_bad))
            session.format = fmt
            session._index()
            return session
        events: list[dict] = []
        results = 0
        partial = False
        stream = iter_any(
            path, skip_bad, max_output_chars=max_output_chars, redact=redact, fmt=fmt
        )
        for event in stream:
            events.append(event)
            if max_steps is not None and event.get("type") == TOOL_RESULT:
                results += 1
                if results >= max_steps:
                    partial = True
                    stream.close()
                    break
        session = cls(path=path, events=events)
        session.partial = partial
        session.format = fmt
        session._index()
        return session

    def _add_usage(self, event: dict) -> None:
        total = self.usage or {
            "input": 0, "output": 0, "cache_read": 0, "cache_creation": 0, "calls": 0
        }
        for dst, src in (
            ("input", "input_tokens"),
            ("output", "output_tokens"),
            ("cache_read", "cache_read_tokens"),
            ("cache_creation", "cache_creation_tokens"),
        ):
            v = event.get(src)
            if isinstance(v, int) and not isinstance(v, bool) and v >= 0:
                total[dst] += v
        total["calls"] += 1
        self.usage = total

    @property
    def total_tokens(self) -> int:
        u = self.usage
        return sum(u.get(k, 0) for k in ("input", "output", "cache_read", "cache_creation"))

    def _index(self) -> None:
        self.usage = {}
        steps: list[Step] = []
        by_call_id: dict[Any, Step] = {}
        pending_results: dict[Any, dict] = {}
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
            elif etype == USAGE:
                self._add_usage(event)
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
                found = by_call_id.get(call_id)
                if found is not None:
                    found.result = event
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
