"""Session recorder: wraps a tool-calling loop and writes a JSONL trace.

Usage::

    from redbg import Recorder

    with Recorder("session.jsonl", agent="my-agent") as rec:
        rec.prompt("user", "What is in main.py?")
        call = rec.tool_call("read_file", {"path": "main.py"})
        try:
            text = open("main.py").read()
        except OSError as exc:
            rec.tool_result(call, ok=False, error=str(exc))
        else:
            rec.tool_result(call, ok=True, output=text)
        rec.response("main.py defines the entry point...")

The recorder streams events to disk as they happen (it never holds the
session in memory), applies secret redaction and output truncation at
record time, and is safe to use from multiple threads.
"""

from __future__ import annotations

import functools
import gzip
import hashlib
import json
import threading
import uuid

from .redact import (
    DEFAULT_KEY_RE,
    DEFAULT_VALUE_RES,
    redact_event,
)
from .schema import (
    NOTE,
    PROMPT,
    RESPONSE,
    SESSION_END,
    SESSION_START,
    TOOL_CALL,
    TOOL_RESULT,
    new_event,
)

DEFAULT_MAX_OUTPUT_CHARS = 20_000


def _json_safe(obj):
    """Coerce anything into JSON-serializable form; never raises."""
    try:
        json.dumps(obj)
        return obj
    except (TypeError, ValueError):
        pass
    if isinstance(obj, dict):
        return {str(k): _json_safe(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [_json_safe(v) for v in obj]
    return repr(obj)


def _sha256_hex(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class Recorder:
    """Incremental JSONL session recorder (context manager)."""

    def __init__(
        self,
        path: str,
        agent: str = "agent",
        meta: dict | None = None,
        max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
        redact: bool = True,
        key_re=DEFAULT_KEY_RE,
        value_res: list | None = None,
    ):
        self.path = path
        self.agent = agent
        self.meta = dict(meta or {})
        self.max_output_chars = max_output_chars
        self.redact = redact
        self.key_re = key_re
        self.value_res = value_res if value_res is not None else DEFAULT_VALUE_RES
        self._lock = threading.RLock()
        self._handle = None
        self._step = 0
        self._pending: dict[str, int] = {}  # call_id -> step number
        self._tool_names: dict[str, str] = {}  # call_id -> tool name
        self._redactions = 0
        self.session_id = uuid.uuid4().hex

    # -- lifecycle ------------------------------------------------------
    def __enter__(self) -> Recorder:
        if self.path.endswith(".gz"):
            self._handle = gzip.open(self.path, "wt", encoding="utf-8")
        else:
            self._handle = open(self.path, "w", encoding="utf-8")
        self._write(
            new_event(
                SESSION_START,
                session_id=self.session_id,
                agent=self.agent,
                meta=_json_safe(self.meta),
            )
        )
        return self

    def __exit__(self, exc_type, exc, tb) -> bool:
        status = "ok" if exc_type is None else "error"
        fields: dict = {
            "session_id": self.session_id,
            "status": status,
            "steps": self._step,
        }
        if exc is not None:
            fields["error"] = f"{exc_type.__name__}: {exc}"
        try:
            self._write(new_event(SESSION_END, **fields))
        finally:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
        return False  # never swallow exceptions

    # -- internals ------------------------------------------------------
    def _write(self, event: dict) -> None:
        if self._handle is None:
            raise RuntimeError("Recorder is not open; use it as a context manager")
        if self.redact:
            event, n = redact_event(event, self.key_re, self.value_res)
            self._redactions += n
        with self._lock:
            self._handle.write(json.dumps(_json_safe(event)) + "\n")
            self._handle.flush()

    def _truncate(self, text: str) -> tuple[str, str]:
        """Return (possibly truncated text, sha256 of the full text)."""
        digest = _sha256_hex(text)
        if self.max_output_chars >= 0 and len(text) > self.max_output_chars:
            text = (
                text[: self.max_output_chars]
                + f"\n...[truncated {len(text) - self.max_output_chars} chars "
                + f"of {len(text)} total, sha256={digest}]"
            )
        return text, digest

    def _truncate_deep(self, obj):
        """Truncate long strings anywhere inside args (anti-blowup)."""
        if isinstance(obj, str):
            if self.max_output_chars >= 0 and len(obj) > self.max_output_chars:
                return (
                    obj[: self.max_output_chars]
                    + f"...[truncated {len(obj) - self.max_output_chars} "
                    + f"of {len(obj)} chars]"
                )
            return obj
        if isinstance(obj, dict):
            return {k: self._truncate_deep(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self._truncate_deep(v) for v in obj]
        return obj

    # -- public API -----------------------------------------------------
    def prompt(self, role: str, text: str) -> str:
        text, _ = self._truncate(text)
        event = new_event(PROMPT, session_id=self.session_id, role=role, text=text)
        self._write(event)
        return event["id"]

    def response(self, text: str, model: str | None = None) -> str:
        text, _ = self._truncate(text)
        fields: dict = {"session_id": self.session_id, "text": text}
        if model is not None:
            fields["model"] = model
        event = new_event(RESPONSE, **fields)
        self._write(event)
        return event["id"]

    def note(self, text: str) -> str:
        text, _ = self._truncate(text)
        event = new_event(NOTE, session_id=self.session_id, text=text)
        self._write(event)
        return event["id"]

    def tool_call(self, tool: str, args: dict | None = None) -> str:
        # The whole call is atomic under the lock so concurrent threads
        # can't interleave step numbers out of file order.
        with self._lock:
            self._step += 1
            step = self._step
            event = new_event(
                TOOL_CALL,
                session_id=self.session_id,
                step=step,
                tool=tool,
                args=self._truncate_deep(_json_safe(args or {})),
            )
            self._pending[event["id"]] = step
            self._tool_names[event["id"]] = tool
            self._write(event)
            return event["id"]

    def tool_result(
        self,
        call_id: str,
        ok: bool,
        output=None,
        error: str | None = None,
    ) -> str:
        with self._lock:
            step = self._pending.pop(call_id, None)
            tool = self._tool_names.pop(call_id, "unknown")
            if step is None:
                raise ValueError(
                    f"unknown tool_call id {call_id!r}: every tool_result must "
                    "reference a call_id returned by tool_call()"
                )
            fields: dict = {
                "session_id": self.session_id,
                "step": step,
                "call_id": call_id,
                "tool": tool,
                "ok": ok,
            }
            if output is not None:
                text = (
                    output
                    if isinstance(output, str)
                    else json.dumps(_json_safe(output), ensure_ascii=False)
                )
                text, digest = self._truncate(text)
                fields["output"] = text
                fields["output_sha256"] = digest
                fields["output_chars"] = len(text)
            if error is not None:
                fields["error"] = str(error)
            event = new_event(TOOL_RESULT, **fields)
            self._write(event)
            return event["id"]

    def wrap(self, func=None, *, name: str | None = None):
        """Decorator: record a tool_call/tool_result around ``func``.

        Can be used bare (``@rec.wrap``) or with a name
        (``@rec.wrap(name="read_file")``). Exceptions are recorded as
        failed results and re-raised.
        """

        def decorator(fn):
            tool = name or fn.__name__

            @functools.wraps(fn)
            def inner(*args, **kwargs):
                payload = {"args": list(args), "kwargs": kwargs}
                call_id = self.tool_call(tool, payload)
                try:
                    result = fn(*args, **kwargs)
                except Exception as exc:  # noqa: BLE001 - record, then re-raise
                    self.tool_result(
                        call_id, ok=False, error=f"{type(exc).__name__}: {exc}"
                    )
                    raise
                self.tool_result(call_id, ok=True, output=result)
                return result

            return inner

        if func is not None:
            return decorator(func)
        return decorator

    # -- stats ----------------------------------------------------------
    @property
    def redactions(self) -> int:
        return self._redactions

    @property
    def steps(self) -> int:
        return self._step
