"""Fork-from-step: re-run a session's tail with modified input.

Two strategies, chosen explicitly because they answer different questions:

``playback`` (default) — Deterministic and free. The recorded model
responses after the fork point are replayed verbatim; tool calls are
*re-executed* against your tool implementations (or a mock). Answers:
"with this different input/tool behavior, does my loop logic still
behave?" It does NOT model how the model would react to the change.

``live`` — Your ``model_fn`` is actually called at each turn. Answers:
"what would the model do now?" Non-deterministic, may cost money, and
the result is a new experiment — not a reproduction. The CLI prints a
warning every time.

Every forked trace carries provenance in ``session_start.meta`` so a
fork can never be mistaken for an original recording.
"""

from __future__ import annotations

import json
import sys
import uuid
from dataclasses import dataclass, field
from typing import Callable

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

PLAYBACK = "playback"
LIVE = "live"
STRATEGIES = (PLAYBACK, LIVE)


@dataclass
class ForkSpec:
    at_step: int
    strategy: str = PLAYBACK
    override_args: dict | None = None
    """Replace the args of the first tool call after the fork point."""
    inject_prompt: str | None = None
    """Insert a user message at the fork point before continuing."""
    tool_impls: dict[str, Callable[[dict], object]] = field(default_factory=dict)
    """Real tool implementations: name -> callable(args) -> output."""
    model_fn: Callable[[list[dict]], object] | None = None
    """Live strategy only: messages -> str (final text) or
    {"tool": name, "args": {...}, "text": "..."} to call a tool."""
    max_steps: int = 50
    allow_mock: bool = True
    """If no implementation exists for a tool, use the echo mock."""


def _echo_mock(tool: str, args: dict) -> dict:
    return {
        "mock": True,
        "tool": tool,
        "args": args,
        "note": "redbg default mock: pass tool_impls for real behavior",
    }


class ForkedSession:
    """The result of a fork: an event list plus provenance."""

    def __init__(
        self, events: list[dict], spec: ForkSpec, source_session_id: str | None
    ):
        self.events = events
        self.spec = spec
        self.source_session_id = source_session_id

    @property
    def steps(self) -> int:
        return sum(1 for e in self.events if e.get("type") == TOOL_CALL)

    def save(self, path: str) -> None:
        import gzip

        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "wt", encoding="utf-8") as handle:
            for event in self.events:
                handle.write(json.dumps(event, default=str) + "\n")


def _execute_tool(tool: str, args: dict, spec: ForkSpec) -> tuple[bool, object]:
    impl = spec.tool_impls.get(tool)
    if impl is None:
        if not spec.allow_mock:
            raise ValueError(
                f"no tool implementation for {tool!r} and allow_mock=False; "
                "pass tool_impls={...} to fork_session"
            )
        return True, _echo_mock(tool, args)
    try:
        return True, impl(args)
    except Exception as exc:  # noqa: BLE001 - recorded as a failed result
        return False, f"{type(exc).__name__}: {exc}"


def fork_session(session, spec: ForkSpec) -> ForkedSession:
    """Fork ``session`` at ``spec.at_step`` and re-run the tail."""
    if spec.strategy not in STRATEGIES:
        raise ValueError(
            f"unknown strategy {spec.strategy!r}; choose from {STRATEGIES}"
        )
    if spec.strategy == LIVE and spec.model_fn is None:
        raise ValueError("live strategy requires model_fn")

    # Resolve the fork point by *positional* step number (the dense
    # numbering the replay engine uses), not by the raw "step" field in
    # the file — hand-edited or merged traces may not number densely.
    try:
        step_obj = session.get_step(spec.at_step)
    except (IndexError, AttributeError) as exc:
        raise ValueError(f"at_step {spec.at_step} out of range") from exc
    if step_obj.call is None:
        raise ValueError(
            f"cannot fork at step {spec.at_step}: it has no tool_call (orphan result)"
        )
    # History = everything before the tool_call of at_step.
    fork_idx = next(i for i, e in enumerate(session.events) if e is step_obj.call)
    history = [
        dict(e)
        for e in session.events[:fork_idx]
        if e.get("type") not in (SESSION_START, SESSION_END)
    ]
    tail = [
        e
        for e in session.events[fork_idx:]
        if e.get("type") not in (SESSION_START, SESSION_END)
    ]
    # Renumber history steps densely: the forked trace must read 1..N even
    # when the source file didn't number densely. (Copies are made above
    # so the source session is never mutated.)
    _renumber_history(history)

    meta = {
        "fork": True,
        "forked_from": getattr(session, "session_id", None),
        "forked_from_path": getattr(session, "path", None),
        "at_step": spec.at_step,
        "strategy": spec.strategy,
        "override_args": spec.override_args,
        "inject_prompt": spec.inject_prompt,
    }
    events: list[dict] = [
        new_event(
            SESSION_START,
            session_id=uuid.uuid4().hex,
            agent=getattr(session, "agent", "agent"),
            meta=meta,
        )
    ]
    events.extend(history)
    if spec.inject_prompt:
        events.append(new_event(PROMPT, role="user", text=spec.inject_prompt))

    if spec.strategy == PLAYBACK:
        _run_playback(events, tail, spec, start_step=spec.at_step)
    else:
        print(
            "warning: live fork is non-deterministic: the model is called "
            "for real and results will vary between runs.",
            file=sys.stderr,
        )
        _run_live(events, spec, start_step=spec.at_step)

    events.append(
        new_event(
            SESSION_END,
            status="ok",
            steps=sum(1 for e in events if e.get("type") == TOOL_CALL),
        )
    )
    return ForkedSession(events, spec, getattr(session, "session_id", None))


def _note_override_no_effect(
    events: list[dict], spec: ForkSpec, first_call: bool, reason: str
) -> None:
    """Warn when --override-args was given but never applied."""
    if spec.override_args is not None and first_call:
        events.append(
            new_event(
                NOTE,
                text="[redbg] override_args had no effect: " + reason,
            )
        )


def _renumber_history(history: list[dict]) -> None:
    """Rewrite step numbers in copied history events to 1..N densely."""
    renumber: dict[str, int] = {}
    next_n = 0
    for event in history:
        if event.get("type") == TOOL_CALL:
            next_n += 1
            renumber[event.get("id")] = next_n
            event["step"] = next_n
        elif event.get("type") == TOOL_RESULT:
            if event.get("call_id") in renumber:
                event["step"] = renumber[event["call_id"]]


def _run_playback(
    events: list[dict], tail: list[dict], spec: ForkSpec, start_step: int
) -> None:
    step = start_step
    first_call = True
    for event in tail:
        etype = event.get("type")
        if etype == TOOL_RESULT:
            continue  # replaced by fresh execution; see below
        elif etype == TOOL_CALL:
            args = dict(event.get("args", {}))
            if first_call and spec.override_args is not None:
                args = dict(spec.override_args)
            first_call = False
            tool = event.get("tool", "unknown")
            call_id = uuid.uuid4().hex
            events.append(
                new_event(TOOL_CALL, step=step, tool=tool, args=args, id=call_id)
            )
            ok, output = _execute_tool(tool, args, spec)
            out_text = (
                output
                if isinstance(output, str)
                else json.dumps(output, default=str, ensure_ascii=False)
            )
            result_fields: dict = {
                "step": step,
                "call_id": call_id,
                "tool": tool,
                "ok": ok,
            }
            if ok:
                result_fields["output"] = out_text
            else:
                result_fields["error"] = out_text
            events.append(new_event(TOOL_RESULT, **result_fields))
            step += 1
        else:
            # PROMPT / RESPONSE / NOTE, and any unknown event type, are
            # replayed verbatim — the fork preserves what it cannot interpret.
            events.append(dict(event))
        if step - start_step >= spec.max_steps:
            events.append(
                new_event(
                    NOTE, text=f"[redbg] fork stopped: max_steps={spec.max_steps}"
                )
            )
            break


def _history_messages(events: list[dict]) -> list[dict]:
    messages: list[dict] = []
    for event in events:
        etype = event.get("type")
        if etype == PROMPT:
            messages.append(
                {"role": event.get("role", "user"), "content": event.get("text", "")}
            )
        elif etype == RESPONSE:
            messages.append({"role": "assistant", "content": event.get("text", "")})
        elif etype == TOOL_CALL:
            messages.append(
                {
                    "role": "assistant",
                    "content": None,
                    "tool_call": {
                        "name": event.get("tool"),
                        "args": event.get("args", {}),
                    },
                }
            )
        elif etype == TOOL_RESULT:
            content = event.get("output") or event.get("error") or ""
            messages.append(
                {
                    "role": "tool",
                    "name": event.get("tool", "unknown"),
                    "content": content,
                }
            )
    return messages


def _run_live(events: list[dict], spec: ForkSpec, start_step: int) -> None:
    assert spec.model_fn is not None
    messages = _history_messages(events)
    step = start_step
    first_call = True
    for _ in range(spec.max_steps):
        reply = spec.model_fn(messages)
        if isinstance(reply, str):
            events.append(new_event(RESPONSE, text=reply))
            messages.append({"role": "assistant", "content": reply})
            _note_override_no_effect(
                events, spec, first_call, "the model made no tool calls"
            )
            return
        if not isinstance(reply, dict) or "tool" not in reply:
            raise ValueError(
                "model_fn must return str (final text) or "
                '{"tool": name, "args": {...}, "text": "..."}; '
                f"got {type(reply).__name__}"
            )
        tool = reply["tool"]
        args = dict(reply.get("args", {}))
        if first_call and spec.override_args is not None:
            args = dict(spec.override_args)
        first_call = False
        if reply.get("text"):
            events.append(new_event(RESPONSE, text=reply["text"]))
        call_id = uuid.uuid4().hex
        events.append(new_event(TOOL_CALL, step=step, tool=tool, args=args, id=call_id))
        messages.append(
            {
                "role": "assistant",
                "content": reply.get("text"),
                "tool_call": {"name": tool, "args": args},
            }
        )
        ok, output = _execute_tool(tool, args, spec)
        out_text = (
            output
            if isinstance(output, str)
            else json.dumps(output, default=str, ensure_ascii=False)
        )
        result_fields: dict = {"step": step, "call_id": call_id, "tool": tool, "ok": ok}
        if ok:
            result_fields["output"] = out_text
        else:
            result_fields["error"] = out_text
        events.append(new_event(TOOL_RESULT, **result_fields))
        messages.append({"role": "tool", "name": tool, "content": out_text})
        step += 1
    events.append(
        new_event(NOTE, text=f"[redbg] fork stopped: max_steps={spec.max_steps}")
    )
    _note_override_no_effect(events, spec, first_call, "the model made no tool calls")
