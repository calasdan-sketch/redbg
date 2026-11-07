"""Native readers for other tools' session logs.

redbg opens, diffs, checks, scans and exports these directly — no convert
step — by streaming each line into redbg events:

* ``claude-code``  Claude Code transcripts (``~/.claude/projects/**.jsonl``)
* ``codex``        Codex CLI rollout files (``rollout-*.jsonl``)
* ``messages``     OpenAI chat-completions / Anthropic Messages arrays
                   (a JSON array, ``{"messages": [...]}``, or JSONL of messages)
* ``otel``         OTel / Langfuse-shaped exports (see ``importer``)

Design rules for untrusted, huge, half-written logs:

* **Streaming.** One line in memory at a time; tool outputs longer than
  ``max_output_chars`` are cut (SHA-256 of the full text kept) so a 100 MB
  transcript does not become a 100 MB object graph.
* **Schema-drift tolerant.** Unknown line types and unknown block types are
  counted, never fatal. Missing fields degrade to ``unknown`` rather than
  raising.
* **Crash tolerant.** A truncated final line (the normal state of a log
  whose writer was killed) is reported, not raised; the session then ends
  with status ``truncated`` so ``redbg check`` fails closed.
* **Redact before truncate.** With ``redact=True`` secrets are removed from
  the full text first, so a cut can never leave half of a PEM block behind.

The field mappings come from the log formats as we have seen them; vendors
change them without notice. Treat an unrecognised shape as a bug report,
not as data loss: nothing is silently dropped without being counted in the
``meta.skipped`` map of the session start event.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from .replay import open_trace
from .schema import (
    EVENT_TYPES,
    NOTE,
    PROMPT,
    RESPONSE,
    SESSION_END,
    SESSION_START,
    TOOL_CALL,
    TOOL_RESULT,
    USAGE,
    new_event,
)

DEFAULT_MAX_OUTPUT_CHARS = 20_000
NATIVE = "redbg"
CLAUDE_CODE = "claude-code"
CODEX = "codex"
MESSAGES = "messages"
OTEL = "otel"
FORMATS = (NATIVE, CLAUDE_CODE, CODEX, MESSAGES, OTEL)

_CC_TYPES = frozenset(
    {
        "user",
        "assistant",
        "system",
        "summary",
        "attachment",
        "queue-operation",
        "file-history-snapshot",
        "custom-title",
        "last-prompt",
        "mode",
        "progress",
    }
)
_CODEX_TYPES = frozenset(
    {"session_meta", "response_item", "event_msg", "turn_context", "compacted"}
)
_SNIFF_LINES = 40


# ---------------------------------------------------------------------------
# Format detection
# ---------------------------------------------------------------------------


def _classify_line(obj) -> str | None:
    if not isinstance(obj, dict):
        return None
    t = obj.get("type")
    if not isinstance(t, str):
        t = None  # hostile/garbled type (list, dict...): unhashable below
    if t in EVENT_TYPES and "v" in obj and "id" in obj:
        return NATIVE
    if t in _CODEX_TYPES and isinstance(obj.get("payload"), dict):
        return CODEX
    if t in _CC_TYPES and ("sessionId" in obj or "uuid" in obj or "message" in obj):
        return CLAUDE_CODE
    if t == "summary" and "leafUuid" in obj:
        return CLAUDE_CODE
    if obj.get("role") in ("user", "assistant", "system", "tool") and (
        "content" in obj or "tool_calls" in obj
    ):
        return MESSAGES
    if "payload" in obj and obj.get("type") == "message":
        return CODEX  # early Codex rollouts had bare items
    return None


_SNIFF_LINE_CAP = 1 << 22  # 4 MB of one line is plenty to recognise a format


def _classify_oversized(prefix: str) -> str | None:
    """Recognise a format from the start of a line too big to parse here."""
    if '"v"' in prefix[:200] and '"id"' in prefix[:400] and '"type"' in prefix[:600]:
        return NATIVE
    if '"sessionId"' in prefix or '"parentUuid"' in prefix:
        return CLAUDE_CODE
    if '"payload"' in prefix and '"timestamp"' in prefix:
        return CODEX
    return None


def sniff(path: str) -> str:
    """Return which format ``path`` is. Defaults to ``redbg`` (native).

    Looks at up to 40 non-empty lines (each read up to 4 MB), so a log
    that opens with one enormous line is still recognised.
    """
    votes: dict[str, int] = {}
    seen = 0
    first_char = ""
    head_text = ""
    with open_trace(path) as handle:
        while seen < _SNIFF_LINES:
            line = handle.readline(_SNIFF_LINE_CAP)
            if not line:
                break
            stripped = line.strip().lstrip("\ufeff")
            if not stripped:
                continue
            if not first_char:
                first_char = stripped[0]
                head_text = stripped[: 1 << 16]
                if first_char == "[":
                    # A JSON array: chat messages carry "role"; span lists do not.
                    # (A one-line array followed by more lines is JSONL noise.)
                    guess = MESSAGES if '"role"' in head_text else OTEL
                    try:
                        json.loads(stripped)
                    except (json.JSONDecodeError, RecursionError):
                        return guess  # a multi-line (pretty-printed) array
                    if not any(handle.readline(1024).strip() for _ in range(1)):
                        return guess  # the whole file is that one array
            seen += 1
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, RecursionError):
                if len(line) >= _SNIFF_LINE_CAP:
                    kind = _classify_oversized(stripped)
                    if kind == NATIVE:
                        return NATIVE
                    if kind:
                        votes[kind] = votes.get(kind, 0) + 1
                continue
            if isinstance(obj, dict) and obj.get("type") is None:
                if any(k in obj for k in ("observations", "spans", "traces")):
                    return OTEL
                if isinstance(obj.get("messages"), list):
                    return MESSAGES
            kind = _classify_line(obj)
            if kind == NATIVE:
                return NATIVE
            if kind:
                votes[kind] = votes.get(kind, 0) + 1
    if votes:
        return max(votes, key=votes.get)
    if first_char == "{":
        # A pretty-printed single JSON document (first line is just "{").
        try:
            with open_trace(path) as handle:
                doc = json.load(handle)
        except (json.JSONDecodeError, RecursionError, MemoryError, OSError):
            return NATIVE
        if isinstance(doc, dict):
            if any(k in doc for k in ("observations", "spans", "traces")):
                return OTEL
            if isinstance(doc.get("messages"), list):
                return MESSAGES
    return NATIVE


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _epoch(ts) -> float | None:
    """ISO-8601 (or epoch seconds/ms) -> epoch seconds; None if unparseable."""
    if isinstance(ts, (int, float)) and not isinstance(ts, bool):
        return float(ts) / 1000.0 if ts > 1e11 else float(ts)
    if not isinstance(ts, str) or not ts:
        return None
    try:
        s = ts[:-1] + "+00:00" if ts.endswith("Z") else ts
        # Python 3.9-3.10 fromisoformat wants 3 or 6 fractional digits.
        if "." in s:
            head, _, rest = s.partition(".")
            frac = ""
            i = 0
            while i < len(rest) and rest[i].isdigit():
                frac += rest[i]
                i += 1
            s = head + "." + (frac + "000000")[:6] + rest[i:]
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, OverflowError, OSError):
        return None


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False, default=str)
    except (TypeError, ValueError, RecursionError):
        return str(value)


def _blocks_text(content) -> str:
    """Flatten message/tool-result content (str | list of blocks) to text."""
    if isinstance(content, str):
        return content
    if isinstance(content, dict):
        content = [content]
    if not isinstance(content, list):
        return _as_text(content)
    parts: list[str] = []
    for block in content:
        if isinstance(block, str):
            parts.append(block)
        elif isinstance(block, dict):
            btype = block.get("type")
            if btype in ("text", "input_text", "output_text"):
                parts.append(_as_text(block.get("text")))
            elif btype == "image" or btype == "input_image" or btype == "image_url":
                parts.append("[image omitted]")
            elif btype == "tool_reference":
                parts.append(f"[tool_reference {block.get('tool_name', '')}]")
            elif "text" in block:
                parts.append(_as_text(block.get("text")))
            else:
                parts.append(f"[{btype or 'block'} omitted]")
        else:
            parts.append(_as_text(block))
    return "\n".join(p for p in parts if p)


class _Builder:
    """Shared event assembly: step numbering, truncation, optional redaction."""

    def __init__(self, max_output_chars: int, redact: bool, fmt: str):
        self.max_output_chars = max_output_chars
        self.redact = redact
        self.fmt = fmt
        self.step = 0
        self.calls: dict[str, dict] = {}
        self.usage_seen: dict[str, dict[str, int]] = {}
        self.skipped: dict[str, int] = {}
        self.started = False
        self.last_mono = 0.0
        self.redactions = 0
        if redact:
            from .redact import DEFAULT_KEY_RE, DEFAULT_VALUE_RES, redact_value

            self._rv = redact_value
            self._key_re = DEFAULT_KEY_RE
            self._value_res = DEFAULT_VALUE_RES

    def skip(self, kind) -> None:
        kind = str(kind)[:40]
        self.skipped[kind] = self.skipped.get(kind, 0) + 1

    def mono(self, ts) -> float:
        value = _epoch(ts)
        if value is not None:
            self.last_mono = value
        return self.last_mono

    def _scrub(self, key: str, value):
        if not self.redact:
            return value
        count = [0]
        out = self._rv(key, value, self._key_re, self._value_res, count)[0]
        self.redactions += count[0]
        return out

    def cut(self, text: str) -> tuple[str, str | None]:
        """(maybe-truncated text, sha256 of the full text or None if short)."""
        if len(text) <= self.max_output_chars:
            return text, None
        digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        kept = text[: self.max_output_chars]
        return (
            kept + f"\n...[truncated {len(text) - len(kept)} chars of "
            f"{len(text)} total, sha256={digest}]",
            digest,
        )

    def start(self, **meta) -> dict:
        self.started = True
        meta["format"] = self.fmt
        sid = meta.pop("session_id", None)
        ev = new_event(SESSION_START, agent=self.fmt, meta=meta)
        if sid:
            ev["session_id"] = sid
        return ev

    def text_event(self, etype: str, text: str, ts, **extra) -> dict:
        text = self._scrub("text", text)
        text, _ = self.cut(text)
        ev = new_event(etype, text=text, **extra)
        if ts:
            ev["ts"] = ts if isinstance(ts, str) else str(ts)
        ev["mono"] = self.mono(ts)
        return ev

    def usage_delta(self, message_id, usage, model, ts):
        """A USAGE event with the *new* tokens of an assistant message.

        Claude Code writes one line per content block of the same message,
        each repeating that message's ``usage`` (sometimes still growing),
        so the event carries only what exceeds what was already counted for
        this message id: the session total stays right either way.
        """
        if not isinstance(usage, dict):
            return None
        names = {
            "input_tokens": "input_tokens",
            "output_tokens": "output_tokens",
            "cache_read_input_tokens": "cache_read_tokens",
            "cache_creation_input_tokens": "cache_creation_tokens",
        }
        now = {}
        for src, dst in names.items():
            v = usage.get(src)
            now[dst] = v if isinstance(v, int) and not isinstance(v, bool) and 0 <= v < 10**12 else 0
        key = message_id if isinstance(message_id, str) and message_id else None
        before = self.usage_seen.get(key, {}) if key else {}
        delta = {k: max(0, now[k] - before.get(k, 0)) for k in now}
        if key:
            self.usage_seen[key] = {k: max(now[k], before.get(k, 0)) for k in now}
        if not any(delta.values()):
            return None
        ev = new_event(USAGE, **delta)
        if isinstance(model, str):
            ev["model"] = model
        if isinstance(ts, str) and ts:
            ev["ts"] = ts
        ev["mono"] = self.mono(ts)
        return ev

    def call(self, call_id: str, tool, args, ts, **extra) -> dict:
        self.step += 1
        tool = tool if isinstance(tool, str) and tool else "unknown"
        if not isinstance(args, dict):
            args = {"input": args} if args is not None else {}
        args = self._scrub("args", args)
        ev = new_event(TOOL_CALL, step=self.step, tool=tool, args=args, **extra)
        ev["id"] = call_id
        if isinstance(ts, str) and ts:
            ev["ts"] = ts
        ev["mono"] = self.mono(ts)
        self.calls[call_id] = {"step": self.step, "tool": tool}
        return ev

    def result(self, call_id: str, text: str, ok: bool, ts) -> dict:
        info = self.calls.get(call_id)
        text = self._scrub("output", text)
        shown, digest = self.cut(text)
        fields: dict = {
            "step": info["step"] if info else 0,
            "call_id": call_id,
            "tool": info["tool"] if info else "unknown",
            "ok": ok,
            "output": shown,
        }
        if not ok:
            fields["error"] = shown[:2000]
        if digest is None:
            digest = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()
        fields["output_sha256"] = digest
        ev = new_event(TOOL_RESULT, **fields)
        if isinstance(ts, str) and ts:
            ev["ts"] = ts
        ev["mono"] = self.mono(ts)
        return ev


def _read_lines(path: str, builder: _Builder, state: dict):
    """Yield parsed JSON objects per line; tolerate bad / truncated lines."""
    bad = 0
    last_bad_is_tail = False
    with open_trace(path) as handle:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except (json.JSONDecodeError, RecursionError):
                bad += 1
                last_bad_is_tail = True
                continue
            last_bad_is_tail = False
            yield obj
    state["bad_lines"] = bad
    state["truncated_tail"] = last_bad_is_tail


def _finish(builder: _Builder, state: dict, calls_open: bool = False):
    if builder.skipped or state.get("bad_lines"):
        bits = [f"{k}={v}" for k, v in sorted(builder.skipped.items())]
        if state.get("bad_lines"):
            bits.append(f"unparseable lines={state['bad_lines']}")
        yield new_event(
            NOTE, text="[redbg] ignored while reading " + builder.fmt + ": " + ", ".join(bits)
        )
    if state.get("truncated_tail"):
        yield new_event(
            NOTE,
            text="[redbg] the last line is cut off (log writer stopped mid-write); "
            "everything before it is shown",
        )
    status = "truncated" if state.get("truncated_tail") else "ok"
    yield new_event(SESSION_END, status=status, steps=builder.step)


# ---------------------------------------------------------------------------
# Claude Code
# ---------------------------------------------------------------------------


def _cc_blocks(builder: _Builder, role: str, content, obj: dict):
    """Turn one Claude Code message's content into events."""
    ts = obj.get("timestamp")
    extra = {"sidechain": True} if obj.get("isSidechain") else {}
    if isinstance(content, str):
        content = [{"type": "text", "text": content}]
    if not isinstance(content, list):
        builder.skip(f"{role}-content")
        return
    for block in content:
        if not isinstance(block, dict):
            builder.skip("block")
            continue
        btype = block.get("type")
        if btype == "text":
            text = block.get("text")
            if not isinstance(text, str) or not text.strip():
                continue
            if role == "assistant":
                ev = builder.text_event(RESPONSE, text, ts, **extra)
                model = (obj.get("message") or {}).get("model")
                if isinstance(model, str):
                    ev["model"] = model
                yield ev
            else:
                if obj.get("isCompactSummary"):
                    yield builder.text_event(NOTE, "[compacted summary] " + text, ts)
                elif obj.get("isMeta"):
                    builder.skip("meta-user")
                else:
                    yield builder.text_event(PROMPT, text, ts, role="user", **extra)
        elif btype == "tool_use":
            cid = block.get("id")
            if not isinstance(cid, str) or not cid:
                builder.skip("tool_use-no-id")
                continue
            yield builder.call(cid, block.get("name"), block.get("input"), ts, **extra)
        elif btype == "tool_result":
            cid = block.get("tool_use_id")
            if not isinstance(cid, str):
                builder.skip("tool_result-no-id")
                continue
            ok = not bool(block.get("is_error"))
            yield builder.result(cid, _blocks_text(block.get("content")), ok, ts)
        elif btype in ("thinking", "redacted_thinking"):
            builder.skip("thinking")
        elif btype == "image":
            if role == "user":
                yield builder.text_event(PROMPT, "[image omitted]", ts, role="user")
        else:
            builder.skip(f"block:{btype}")


def iter_claude_code(path, builder: _Builder, state: dict):
    for obj in _read_lines(path, builder, state):
        if not isinstance(obj, dict):
            builder.skip("non-object")
            continue
        t = obj.get("type")
        if not isinstance(t, str):
            builder.skip("bad-type")
            continue
        if not builder.started and (obj.get("sessionId") or t in ("user", "assistant")):
            yield builder.start(
                session_id=obj.get("sessionId"),
                version=obj.get("version"),
                cwd=obj.get("cwd"),
                git_branch=obj.get("gitBranch"),
            )
        if t in ("user", "assistant"):
            msg = obj.get("message")
            if not isinstance(msg, dict):
                builder.skip(f"{t}-no-message")
                continue
            if t == "assistant":
                uev = builder.usage_delta(
                    msg.get("id"), msg.get("usage"), msg.get("model"), obj.get("timestamp")
                )
                if uev is not None:
                    yield uev
            yield from _cc_blocks(builder, t, msg.get("content"), obj)
        elif t == "system":
            sub = obj.get("subtype")
            if sub == "compact_boundary":
                yield builder.text_event(
                    NOTE, "[conversation compacted]", obj.get("timestamp")
                )
            else:
                builder.skip(f"system:{sub}")
        elif t == "summary":
            text = obj.get("summary")
            if isinstance(text, str):
                yield builder.text_event(NOTE, "[summary] " + text, None)
        else:
            builder.skip(t)


# ---------------------------------------------------------------------------
# Codex rollouts
# ---------------------------------------------------------------------------


def _codex_args(raw):
    if isinstance(raw, str):
        try:
            val = json.loads(raw)
            return val if isinstance(val, dict) else {"input": val}
        except (json.JSONDecodeError, RecursionError):
            return {"input": raw}
    return raw if isinstance(raw, dict) else {"input": raw}


def _codex_output(raw) -> tuple[str, bool]:
    """(text, ok) from a function_call_output payload field."""
    ok = True
    if isinstance(raw, dict):
        if raw.get("success") is False:
            ok = False
        text = _blocks_text(raw.get("content", raw.get("output", raw)))
        return text, ok
    text = _as_text(raw)
    stripped = text.lstrip()
    if stripped.startswith("{") and '"output"' in stripped[:200]:
        try:
            doc = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            return text, ok
        if isinstance(doc, dict) and "output" in doc:
            meta = doc.get("metadata")
            if isinstance(meta, dict) and isinstance(meta.get("exit_code"), int):
                ok = meta["exit_code"] == 0
            return _as_text(doc["output"]), ok
    return text, ok


def iter_codex(path, builder: _Builder, state: dict):
    for obj in _read_lines(path, builder, state):
        if not isinstance(obj, dict):
            builder.skip("non-object")
            continue
        ts = obj.get("timestamp")
        t = obj.get("type")
        payload = obj.get("payload")
        if t == "session_meta" and isinstance(payload, dict):
            if not builder.started:
                yield builder.start(
                    session_id=payload.get("id"),
                    version=payload.get("cli_version"),
                    cwd=payload.get("cwd"),
                )
            continue
        if not builder.started:
            yield builder.start()
        if t != "response_item" or not isinstance(payload, dict):
            if t == "compacted":
                yield builder.text_event(NOTE, "[conversation compacted]", ts)
            else:
                builder.skip(t)  # event_msg / turn_context duplicate response items
            continue
        ptype = payload.get("type")
        if ptype == "message":
            text = _blocks_text(payload.get("content"))
            role = payload.get("role")
            if not text.strip():
                continue
            if role == "assistant":
                yield builder.text_event(RESPONSE, text, ts)
            elif role == "user":
                yield builder.text_event(PROMPT, text, ts, role="user")
            else:
                builder.skip(f"message:{role}")
        elif ptype in ("function_call", "custom_tool_call"):
            cid = payload.get("call_id") or payload.get("id")
            if not isinstance(cid, str):
                builder.skip("call-no-id")
                continue
            raw = payload.get("arguments", payload.get("input"))
            yield builder.call(cid, payload.get("name"), _codex_args(raw), ts)
        elif ptype == "local_shell_call":
            cid = payload.get("call_id") or payload.get("id")
            action = payload.get("action")
            if not isinstance(cid, str):
                builder.skip("call-no-id")
                continue
            yield builder.call(cid, "shell", action if isinstance(action, dict) else {}, ts)
        elif ptype in ("function_call_output", "custom_tool_call_output"):
            cid = payload.get("call_id")
            if not isinstance(cid, str):
                builder.skip("output-no-id")
                continue
            text, ok = _codex_output(payload.get("output"))
            yield builder.result(cid, text, ok, ts)
        elif ptype == "reasoning":
            builder.skip("reasoning")
        else:
            builder.skip(f"item:{ptype}")


# ---------------------------------------------------------------------------
# Chat-message arrays (OpenAI chat completions / Anthropic Messages)
# ---------------------------------------------------------------------------


def _iter_messages_source(path: str, state: dict):
    with open_trace(path) as handle:
        first = handle.readline()
        while first and not first.strip():
            first = handle.readline()
    lead = first.lstrip("\ufeff \t\r\n")[:1]
    whole = lead == "["
    if lead == "{":
        try:
            obj = json.loads(first)
            whole = isinstance(obj, dict) and isinstance(obj.get("messages"), list)
        except (json.JSONDecodeError, RecursionError):
            whole = True  # a pretty-printed single document
    if whole:
        with open_trace(path) as handle:
            try:
                doc = json.load(handle)
            except (json.JSONDecodeError, RecursionError):
                doc = None
                state["bad_lines"] = 1
                state["truncated_tail"] = True
        if isinstance(doc, dict) and isinstance(doc.get("messages"), list):
            yield from doc["messages"]
        elif isinstance(doc, list):
            yield from doc
        elif isinstance(doc, dict):
            yield doc
        return
    with open_trace(path) as handle:
        bad_tail = False
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except (json.JSONDecodeError, RecursionError):
                bad_tail = True
                state["bad_lines"] = state.get("bad_lines", 0) + 1
                continue
            bad_tail = False
            yield obj
        state["truncated_tail"] = bad_tail


def iter_messages(path, builder: _Builder, state: dict):
    yield builder.start()
    for i, msg in enumerate(_iter_messages_source(path, state)):
        if not isinstance(msg, dict):
            builder.skip("non-object")
            continue
        role = msg.get("role")
        content = msg.get("content")
        if role == "user":
            if isinstance(content, list) and any(
                isinstance(b, dict) and b.get("type") == "tool_result" for b in content
            ):
                yield from _cc_blocks(builder, "user", content, {})
            else:
                text = _blocks_text(content)
                if text.strip():
                    yield builder.text_event(PROMPT, text, None, role="user")
        elif role == "assistant":
            if isinstance(content, list):
                yield from _cc_blocks(builder, "assistant", content, {"message": msg})
            else:
                text = _blocks_text(content)
                if text.strip():
                    yield builder.text_event(RESPONSE, text, None)
            for tc in msg.get("tool_calls") or []:
                if not isinstance(tc, dict):
                    continue
                fn = tc.get("function") if isinstance(tc.get("function"), dict) else {}
                cid = tc.get("id") or f"call_{i}_{builder.step + 1}"
                yield builder.call(
                    str(cid), fn.get("name") or tc.get("name"),
                    _codex_args(fn.get("arguments", tc.get("arguments"))), None,
                )
        elif role == "tool":
            cid = msg.get("tool_call_id")
            if isinstance(cid, str):
                yield builder.result(cid, _blocks_text(content), True, None)
            else:
                builder.skip("tool-no-id")
        elif role == "system":
            builder.skip("system")
        else:
            builder.skip(f"role:{role}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def iter_events(
    path: str,
    fmt: str | None = None,
    max_output_chars: int = DEFAULT_MAX_OUTPUT_CHARS,
    redact: bool = False,
):
    """Stream redbg events from a foreign log (never the native format)."""
    fmt = fmt or sniff(path)
    state: dict = {}
    if fmt == OTEL:
        from .importer import import_events

        with open_trace(path) as handle:
            yield from import_events(json.load(handle))
        return
    builder = _Builder(max_output_chars, redact, fmt)
    reader = {CLAUDE_CODE: iter_claude_code, CODEX: iter_codex, MESSAGES: iter_messages}.get(fmt)
    if reader is None:
        raise ValueError(f"not a foreign format: {fmt!r}")
    started = False
    for ev in reader(path, builder, state):
        started = True
        yield ev
    if not started:
        yield builder.start()
    yield from _finish(builder, state)
