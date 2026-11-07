"""Import external traces into redbg format.

Converts OTel-shaped spans and Langfuse-shaped observations into redbg
events. This is deliberately heuristic and documented as lossy: the goal
is "good enough to diff and replay", not a perfect translation.

Accepted shapes:
- a list of span dicts: ``{"name", "startTime"/"start_time", "endTime",
  "attributes"/"attrs", "status"}``
- ``{"spans": [...]}`` / ``{"traces": [{"spans": [...]}]}``
- Langfuse-style: ``{"observations": [{"type": "SPAN"/"GENERATION",
  "name", "input", "output", "startTime", "endTime"}]}``
"""

from __future__ import annotations

import gzip
import json
import os

from ._fs import finish, name_target, staging_path
from .replay import ensure_distinct
from .schema import (
    NOTE,
    RESPONSE,
    SESSION_END,
    SESSION_START,
    TOOL_CALL,
    TOOL_RESULT,
    new_event,
)


def _as_text(value) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, default=str, ensure_ascii=False)


def _span_times(span: dict) -> tuple:
    start = span.get("startTime", span.get("start_time", span.get("timestamp")))
    end = span.get("endTime", span.get("end_time"))
    return start, end


def _span_attrs(span: dict) -> dict:
    attrs = span.get("attributes", span.get("attrs", {}))
    return attrs if isinstance(attrs, dict) else {}


_TOOL_HINTS = ("tool", "function", "mcp", "action")
_GEN_HINTS = ("llm", "generation", "completion", "chat", "model", "agent")


def _looks_like_tool(name: str, attrs: dict, obs_type: str | None) -> bool:
    lname = name.lower()
    if obs_type == "SPAN" and any(h in lname for h in _TOOL_HINTS):
        return True
    if any(k in attrs for k in ("tool.name", "function.name", "tool.args")):
        return True
    return any(h in lname for h in _TOOL_HINTS)


def _looks_like_generation(name: str, attrs: dict, obs_type: str | None) -> bool:
    if obs_type == "GENERATION":
        return True
    lname = name.lower()
    return any(h in lname for h in _GEN_HINTS)


def _tool_name(name: str, attrs: dict) -> str:
    for key in ("tool.name", "function.name", "tool_name"):
        if key in attrs:
            return str(attrs[key])
    # "tool.read_file" -> "read_file"
    for hint in _TOOL_HINTS:
        prefix = hint + "."
        if name.lower().startswith(prefix):
            return name[len(prefix) :]
    return name


def _tool_args(attrs: dict, span: dict):
    for key in ("tool.args", "function.args", "args", "input"):
        if key in attrs:
            value = attrs[key]
            break
    else:
        value = span.get("input")
    if isinstance(value, str):
        try:
            return json.loads(value)
        except (json.JSONDecodeError, ValueError):
            return {"input": value}
    return value if isinstance(value, dict) else {"input": _as_text(value)}


def _tool_output(attrs: dict, span: dict) -> tuple[bool, str]:
    for key in ("tool.output", "output", "result"):
        if key in attrs:
            return True, _as_text(attrs[key])
    if span.get("output") is not None:
        return True, _as_text(span["output"])
    status = span.get("status", attrs.get("status", ""))
    ok = str(status).lower() not in ("error", "failed", "ko")
    return ok, ""


def import_events(obj) -> list[dict]:
    """Convert a parsed external trace into a list of redbg events."""
    spans: list[dict] = []
    if isinstance(obj, dict):
        if "observations" in obj:  # Langfuse export
            spans = list(obj["observations"])
        elif "spans" in obj:
            spans = list(obj["spans"])
        elif "traces" in obj:
            for trace in obj["traces"]:
                spans.extend(trace.get("spans", []))
        else:
            spans = [obj]
    elif isinstance(obj, list):
        spans = obj
    else:
        raise ValueError("import expects a JSON object or list of spans")

    # Sort best-effort by start time; fall back to given order.
    def _sort_key(span: dict):
        start, _ = _span_times(span)
        return (0, str(start)) if start else (1, "")

    spans = sorted(spans, key=_sort_key)

    events: list[dict] = [
        new_event(SESSION_START, agent="imported", meta={"imported": True})
    ]
    step = 0
    for span in spans:
        if not isinstance(span, dict):
            continue
        name = str(span.get("name", "span"))
        attrs = _span_attrs(span)
        obs_type = span.get("type")
        start, end = _span_times(span)

        if _looks_like_tool(name, attrs, obs_type):
            step += 1
            tool = _tool_name(name, attrs)
            call_id = new_event(TOOL_CALL)["id"]
            call = new_event(
                TOOL_CALL,
                step=step,
                tool=tool,
                args=_tool_args(attrs, span),
                id=call_id,
            )
            if start:
                call["imported_start"] = start
            events.append(call)
            ok, output = _tool_output(attrs, span)
            result_fields: dict = {
                "step": step,
                "call_id": call_id,
                "tool": tool,
                "ok": ok,
            }
            if output:
                result_fields["output"] = output
            events.append(new_event(TOOL_RESULT, **result_fields))
        elif _looks_like_generation(name, attrs, obs_type):
            text = _as_text(attrs.get("output", span.get("output", "")))
            if not text:
                text = _as_text(attrs.get("input", span.get("input", "")))
            events.append(new_event(RESPONSE, text=text, model=name))
        else:
            events.append(
                new_event(NOTE, text=f"[imported span] {name}: {_as_text(attrs)[:500]}")
            )
    events.append(
        new_event(SESSION_END, status="ok", steps=step, meta={"imported": True})
    )
    return events


def import_file(src: str, dst: str, redact: bool = False) -> dict:
    """Convert any supported log to a redbg trace. Returns stats.

    Claude Code / Codex / message-array logs are streamed (constant
    memory); OTel/Langfuse exports are heuristic and lossy.
    """
    from . import formats
    from .replay import iter_any

    ensure_distinct(src, dst)
    fmt = formats.sniff(src)
    if fmt == formats.NATIVE:
        raise ValueError(f"{src!r} is already a redbg trace (nothing to import)")
    events = 0
    steps = 0
    tmp = staging_path(dst)
    opener = gzip.open if dst.endswith(".gz") else open
    try:
        with opener(tmp, "wt", encoding="utf-8", newline="\n") as handle:
            for event in iter_any(src, fmt=fmt, redact=redact):
                handle.write(json.dumps(event, default=str, ensure_ascii=False) + "\n")
                events += 1
                steps += event.get("type") == TOOL_CALL
        finish(tmp, dst)  # never leave a half-written trace at dst
    except OSError as exc:
        raise name_target(exc, tmp, dst) from None
    finally:
        if tmp != dst and os.path.exists(tmp):
            os.remove(tmp)
    return {"events": events, "steps": steps, "dst": dst, "format": fmt}
