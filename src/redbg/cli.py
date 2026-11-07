"""redbg command-line interface.

Subcommands:
  demo [DIR]          write two example traces to try redbg on
  sessions            list recent Claude Code / Codex transcripts
  replay TRACE        interactive debugger REPL (step next/prev, inspect)
  diff A B            side-by-side divergence report for two sessions
  check TRACE         CI gate: regressions vs --baseline, budgets, loops
  fork TRACE --at N   re-run the tail of a session with modified input
  redact SRC -o DST   strip secrets from a trace
  scan TRACE          audit a trace for likely secrets (exit 1 if found)
  info TRACE          session summary
  import SRC -o DST   convert Claude Code / Codex / chat-message / OTel logs
  why TRACE N         why did the agent make call N? (causal chain)
  audit TRACE         rank the suspicious steps (invented paths, destructive
                      commands, loops, secrets)
  files TRACE         which files each step read / wrote / deleted
  blame TRACE PATH    which steps touched PATH

Every command opens redbg traces, Claude Code transcripts, Codex rollouts and
OpenAI/Anthropic message logs directly (format auto-detected).
"""

from __future__ import annotations

import argparse
import atexit
import json
import os
import re
import runpy
import shutil
import sys
import tempfile
from typing import Any

from . import __version__
from ._fs import explain_oserror
from ._text import clean, md_fence
from .analysis import Breakpoint, blame, explain, file_ledger, run_to_breakpoint
from .audit import audit
from .check import FAIL_ON_CHOICES, CheckRules, run_check, to_github, to_junit
from .diff import diff_to_dict, find_cycles, find_repeats, render_diff
from .fork import ForkSpec, fork_session
from .htmlexport import render_html
from .importer import import_file
from .redact import DEFAULT_VALUE_RES, PII_VALUE_RES, redact_file, scan_file
from .replay import Navigator, Session, ensure_distinct

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def _why_failed(exc: BaseException) -> str:
    """Plain-English text for an error shown to the user."""
    if isinstance(exc, OSError):
        return explain_oserror(exc)
    return str(exc)


def _windows_ansi_ok() -> bool:
    """True if this Windows console understands ANSI colors (tries to turn them on)."""
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x4
        return bool(mode.value & 0x4) or bool(kernel32.SetConsoleMode(handle, mode.value | 0x4))
    except Exception:  # noqa: BLE001 - any failure just means "no color"
        return False


def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR", "") != "" or not sys.stdout.isatty():
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    if os.name == "nt":
        return _windows_ansi_ok()
    return True


def _c(text: str, code: str, enabled: bool) -> str:
    return f"{code}{text}{RESET}" if enabled and code else text


# ---------------------------------------------------------------------------
# Rendering helpers
# ---------------------------------------------------------------------------


def _fmt_ms(ms: float | None) -> str:
    if ms is None:
        return "?"
    if ms < 1000:
        return f"{ms:.1f} ms"
    return f"{ms / 1000:.2f} s"


def _truncate(text: str, limit: int = 2000) -> str:
    # Sanitize *after* truncating so the limit applies to real content,
    # and every display path gets control characters neutralized.
    if len(text) > limit:
        text = text[:limit] + f"\n…[{len(text) - limit} more chars]"
    return clean(text)


def render_step(step, total: int, color: bool, show_context: bool = True) -> str:
    """Render one step the way `s` shows it in the REPL."""
    status = "ok" if step.ok else ("FAIL" if step.ok is False else "no result")
    status_c = _c(status, GREEN if step.ok else RED, color)
    lines = [
        _c(
            f"── step {step.n}/{total} · {clean(step.tool)} · {status_c} · "
            f"{_fmt_ms(step.duration_ms)} ──",
            BOLD,
            color,
        )
    ]
    lines.append(_c("args:", CYAN, color))
    args_json = json.dumps(
        step.args, indent=2, sort_keys=True, ensure_ascii=False, default=str
    )
    lines.append(_truncate(args_json))
    if step.output is not None:
        lines.append(_c(f"output ({len(step.output)} chars):", CYAN, color))
        lines.append(_truncate(step.output))
    if step.error:
        lines.append(_c("error:", RED, color))
        lines.append(_truncate(step.error))
    if show_context:
        if step.response_ctx and step.response_ctx.get("text"):
            lines.append(_c("model said before this call:", DIM, color))
            lines.append(_truncate(step.response_ctx["text"], 600))
        if step.prompt_ctx and step.prompt_ctx.get("text"):
            lines.append(_c("latest user prompt:", DIM, color))
            lines.append(_truncate(step.prompt_ctx["text"], 600))
    return "\n".join(lines)


def render_list(session: Session, color: bool) -> str:
    lines = []
    for step in session.steps:
        mark = "✓" if step.ok else ("✗" if step.ok is False else "?")
        mark = _c(mark, GREEN if step.ok else RED, color)
        lines.append(
            f"{step.n:>4} {mark} {_fmt_ms(step.duration_ms):>10}  {clean(step.tool)}"
        )
    return "\n".join(lines)


def render_info(session: Session, color: bool) -> str:
    tools: dict[str, int] = {}
    failed = 0
    total_ms = 0.0
    for step in session.steps:
        tools[step.tool] = tools.get(step.tool, 0) + 1
        if step.ok is False:
            failed += 1
        if step.duration_ms:
            total_ms += step.duration_ms
    lines = [
        _c(f"session: {clean(session.path)}", BOLD, color),
        f"  agent:      {clean(session.agent)}",
        f"  session id: {clean(session.session_id)}",
        f"  status:     {clean(session.status)}",
        f"  steps:      {len(session.steps)}",
        f"  failed:     {failed}",
        f"  tool time:  {_fmt_ms(total_ms)}",
        f"  prompts:    {len(session.prompts)}",
        f"  responses:  {len(session.responses)}",
        "  tools:      "
        + ", ".join(f"{clean(name)}×{count}" for name, count in sorted(tools.items())),
    ]
    if session.usage:
        u = session.usage
        lines.append(
            f"  tokens:     {u['input']:,} in, {u['output']:,} out, "
            f"{u['cache_read']:,} cache read, {u['cache_creation']:,} cache "
            f"write ({u['calls']} model call(s); counts, not cost)"
        )
    repeats = find_repeats(session)
    if repeats:
        worst = max(repeats, key=lambda r: r.count)
        lines.append(
            _c(
                f"  repeats:    {len(repeats)} run(s) of identical consecutive calls; "
                f"longest {clean(worst.tool)}×{worst.count} "
                f"(steps {worst.first}-{worst.last}) — possible loop",
                YELLOW,
                color,
            )
        )
    cycles = find_cycles(session)
    if cycles:
        worst_c = max(cycles, key=lambda c: c.reps)
        lines.append(
            _c(
                f"  cycles:     {len(cycles)} alternating pattern(s); longest "
                f"[{clean(' -> '.join(worst_c.tools))}]×{worst_c.reps} "
                f"(steps {worst_c.first}-{worst_c.last}) — possible loop",
                YELLOW,
                color,
            )
        )
    return "\n".join(lines)


def _md_inline(text) -> str:
    """Render untrusted text as a Markdown code span it cannot escape.

    Inside a code span nothing is interpreted (no links, HTML or
    emphasis); the delimiter is longer than any backtick run inside.
    """
    text = clean(text).replace("\n", " ")
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    tick = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{tick}{pad}{text}{pad}{tick}"


def export_markdown(session: Session) -> str:
    lines = [
        f"# redbg session: {_md_inline(session.path)}",
        "",
        f"- agent: {_md_inline(session.agent)}",
        f"- session id: {_md_inline(session.session_id)}",
        f"- status: {_md_inline(session.status)}",
        f"- steps: {len(session.steps)}",
        "",
    ]
    for step in session.steps:
        status = "ok" if step.ok else ("FAIL" if step.ok is False else "no result")
        lines.append(
            f"## step {step.n}: {_md_inline(step.tool)} "
            f"({status}, {_fmt_ms(step.duration_ms)})"
        )
        lines.append("")
        args_json = json.dumps(
            step.args, indent=2, sort_keys=True, default=str, ensure_ascii=False
        )
        lines.append(md_fence(clean(args_json), "json"))
        if step.output:
            lines.append("")
            lines.append("<details><summary>output</summary>")
            lines.append("")
            lines.append(md_fence(_truncate(step.output, 4000)))
            lines.append("")
            lines.append("</details>")
        if step.error:
            lines.append("")
            lines.append("**error:**")
            lines.append("")
            lines.append(md_fence(_truncate(step.error, 4000)))
        lines.append("")
    return "\n".join(lines)


def render_explanation(exp, color: bool) -> str:
    def brief(rows):
        return ", ".join(
            f"{n}:{clean(tool)}{'' if ok else ' (FAIL)' if ok is False else ' (?)'}"
            for n, tool, ok in rows
        )

    lines = [_c(f"── why step {exp.step}: {clean(exp.tool)} ──", BOLD, color)]
    lines.append(_c("user asked:", CYAN, color))
    lines.append(_truncate(exp.prompt or "(no prompt recorded before this call)", 500))
    if exp.model_text:
        lines.append(_c("model said just before:", CYAN, color))
        lines.append(_truncate(exp.model_text, 500))
    if exp.turn_steps:
        lines.append(_c("earlier steps in this turn:", CYAN, color))
        lines.append("  " + brief(exp.turn_steps[-12:]))
    lines.append(_c("where the values in this call came from:", CYAN, color))
    if not exp.provenance:
        lines.append("  (no concrete values in the arguments)")
    for prov in exp.provenance:
        mark = _c("??", RED, color) if prov.origin == "nowhere" else "<-"
        origin = (
            "not found in anything the agent had seen (invented, or hidden by "
            "output truncation)"
            if prov.origin == "nowhere"
            else prov.origin
        )
        lines.append(f"  {mark} {_truncate(prov.value, 80)}  {origin}")
    if exp.effects:
        lines.append(_c("effects:", CYAN, color))
        for eff in exp.effects:
            lines.append(f"  {eff.kind} {clean(eff.path)} ({eff.how})")
    if exp.next_steps:
        lines.append(_c("what happened next:", CYAN, color))
        lines.append("  " + brief(exp.next_steps))
    return "\n".join(lines)


def render_ledger(session: Session, color: bool) -> str:
    ledger = file_ledger(session)
    if not ledger:
        return "no file effects found (shell scripts that write files internally are invisible)."
    lines = []
    for path, effs in sorted(ledger.items()):
        hist = " ".join(
            f"{e.kind[0]}{e.step}{'*' if e.how == 'inferred' else ''}"
            + ("!" if e.ok is False else "")
            for e in effs
        )
        lines.append(f"{clean(path)}  {hist}")
    lines.append(
        "legend: r=read w=write d=delete, number=step, *=inferred from a shell "
        "command, !=step failed"
    )
    return "\n".join(lines)


def render_blame(session: Session, path: str, color: bool) -> str:
    if not path:
        return "usage: blame PATH"
    hits = blame(session, path)
    if not hits:
        return f"no step touched {clean(path)}."
    lines = []
    for e in hits:
        by = session.get_step(e.step)
        why = (by.response_ctx or {}).get("text") or ""
        lines.append(
            f"step {e.step:>4}  {e.kind:<6} {clean(e.path)}  [{clean(e.tool)}, {e.how}"
            f"{', FAILED' if e.ok is False else ''}]  "
            + clean(why.strip().replace("\n", " ")[:80])
        )
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# The replay REPL
# ---------------------------------------------------------------------------

HELP = """\
commands:
  n, next        step forward one tool call
  p, prev        step back one tool call
  g, goto N      jump to step N
  l, list        list all steps
  s, show [N]    show step details (default: current step)
  /pattern       search tool/args/output for pattern
  b, break SPEC  stop on: a tool glob (Bash, mcp__*), fail, slow:MS,
                 file:PATH, or ~REGEX      (tb SPEC = one-shot)
  info break     list breakpoints;  delete N  remove breakpoint N
  c, continue    run forward to the next breakpoint
  rc             run backward to the previous breakpoint
  why [N]        why was call N made? prompt, earlier steps, value origins
  files          files touched by each step;  blame PATH = who touched PATH
  t, time        timing table for all steps
  i, info        session summary
  q, quit        quit
  h, help        this help
"""


class Repl:
    def __init__(self, session: Session, color: bool):
        self.nav = Navigator(session)
        self.session = session
        self.color = color
        self.breakpoints: list[Breakpoint] = []
        self._bp_seq = 0

    def _prompt(self) -> str:
        at = self.nav.cursor
        total = self.nav.count
        pos = f"{at}/{total}" if at else f"–/{total}"
        return _c(f"(redbg {pos}) ", BOLD, self.color)

    def _show_current(self) -> None:
        step = self.nav.current()
        if step is None:
            print(
                _c(
                    "at start — use `n` to step into the first tool call.",
                    DIM,
                    self.color,
                )
            )
            return
        print(render_step(step, self.nav.count, self.color))

    def _add_break(self, spec: str, temporary: bool) -> None:
        try:
            bp = Breakpoint.parse(spec, temporary=temporary)
        except ValueError as exc:
            print(_c(f"break: {exc}", RED, self.color))
            return
        self._bp_seq += 1
        bp.number = self._bp_seq
        self.breakpoints.append(bp)
        print(f"breakpoint {bp.number}: {clean(bp.spec)}")

    def _list_breaks(self) -> None:
        if not self.breakpoints:
            print(_c("no breakpoints.", DIM, self.color))
        for bp in self.breakpoints:
            tmp = " (temporary)" if bp.temporary else ""
            print(f"  {bp.number}: {clean(bp.spec)}{tmp}  hits={bp.hits}")

    def _delete_break(self, arg: str) -> None:
        if not arg.strip():
            self.breakpoints.clear()
            print("all breakpoints deleted.")
            return
        try:
            num = int(arg)
        except ValueError:
            print(_c("usage: delete [N]", RED, self.color))
            return
        before = len(self.breakpoints)
        self.breakpoints = [b for b in self.breakpoints if b.number != num]
        print("deleted." if len(self.breakpoints) < before else "no such breakpoint.")

    def _continue(self, reverse: bool) -> None:
        if not self.breakpoints:
            print(_c("no breakpoints set — use `break SPEC` first.", YELLOW, self.color))
            return
        n, bp = run_to_breakpoint(
            self.session, self.nav.cursor, self.breakpoints, reverse=reverse
        )
        if n is None:
            end = "start" if reverse else "end"
            self.nav.cursor = 0 if reverse else self.nav.count
            print(_c(f"no more breakpoint hits before the {end}.", DIM, self.color))
            return
        bp.hits += 1
        if bp.temporary:
            self.breakpoints = [b for b in self.breakpoints if b is not bp]
        step = self.nav.goto(n)
        print(_c(f"hit breakpoint {bp.number} ({clean(bp.spec)})", YELLOW, self.color))
        print(render_step(step, self.nav.count, self.color))

    def run_command(self, raw: str) -> bool:
        """Run one command. Returns False when the REPL should exit."""
        parts = raw.strip().split(None, 1)
        if not parts:
            return True
        cmd, arg = parts[0].lower(), (parts[1] if len(parts) > 1 else "")

        if cmd in ("q", "quit", "exit"):
            return False
        if cmd in ("h", "help", "?"):
            print(HELP)
        elif cmd in ("n", "next"):
            step = self.nav.next()
            if step is None:
                print(_c("end of session.", DIM, self.color))
            else:
                print(render_step(step, self.nav.count, self.color, show_context=False))
        elif cmd in ("p", "prev"):
            step = self.nav.prev()
            if step is None:
                print(_c("at start of session.", DIM, self.color))
            else:
                print(render_step(step, self.nav.count, self.color, show_context=False))
        elif cmd in ("g", "goto"):
            try:
                n = int(arg)
            except ValueError:
                print(_c("usage: goto N", RED, self.color))
                return True
            try:
                step = self.nav.goto(n)
            except IndexError as exc:
                print(_c(str(exc), RED, self.color))
                return True
            print(render_step(step, self.nav.count, self.color))
        elif cmd in ("l", "list"):
            print(render_list(self.session, self.color))
        elif cmd in ("s", "show"):
            if arg:
                try:
                    step = self.session.get_step(int(arg))
                except (ValueError, IndexError) as exc:
                    print(_c(f"bad step: {exc}", RED, self.color))
                    return True
                print(render_step(step, self.nav.count, self.color))
            else:
                self._show_current()
        elif cmd.startswith("/"):
            pattern = raw.strip()[1:]
            hits = self.session.search(pattern)
            if hits:
                print(
                    _c(
                        f"matches at steps: {', '.join(map(str, hits))}",
                        GREEN,
                        self.color,
                    )
                )
            else:
                print(_c("no matches.", DIM, self.color))
        elif cmd in ("t", "time"):
            print(render_list(self.session, self.color))
        elif cmd in ("i", "info"):
            if arg.strip().lower() in ("break", "breaks", "breakpoints"):
                self._list_breaks()
            else:
                print(render_info(self.session, self.color))
        elif cmd in ("b", "break", "tb", "tbreak"):
            self._add_break(arg, temporary=cmd in ("tb", "tbreak"))
        elif cmd in ("delete", "del", "d"):
            self._delete_break(arg)
        elif cmd in ("c", "continue", "rc", "reverse-continue"):
            self._continue(reverse=cmd in ("rc", "reverse-continue"))
        elif cmd == "why":
            try:
                n = int(arg) if arg.strip() else self.nav.cursor
                print(render_explanation(explain(self.session, n), self.color))
            except (ValueError, IndexError) as exc:
                print(_c(f"why: {exc}", RED, self.color))
        elif cmd == "files":
            print(render_ledger(self.session, self.color))
        elif cmd == "blame":
            print(render_blame(self.session, arg.strip(), self.color))
        else:
            print(_c(f"unknown command {cmd!r} — `h` for help.", YELLOW, self.color))
        return True

    def run(self, script: str | None = None) -> None:
        if script:
            for chunk in script.replace(";", "\n").splitlines():
                for cmd in chunk.split("&&"):
                    if not self.run_command(cmd):
                        return
            return
        try:
            import readline  # noqa: F401  (history + editing when available)
        except ImportError:
            pass
        while True:
            try:
                raw = input(self._prompt())
            except (EOFError, KeyboardInterrupt):
                print()
                break
            try:
                if not self.run_command(raw):
                    break
            except BrokenPipeError:
                break


# ---------------------------------------------------------------------------
# Subcommand implementations
# ---------------------------------------------------------------------------


LAZY_BYTES = 4 * 1024 * 1024


def _lazy_limit(args):
    """Stop after step N for ``--show N`` on big plain files only.

    Small files load fully so the ``N/total`` counter stays exact; above
    ``LAZY_BYTES`` the total is shown as ``?`` and the first view appears
    in milliseconds instead of after a full parse.
    """
    if not args.show or args.list or args.export_md or args.export_html:
        return None
    try:
        if args.trace.endswith(".gz") or os.path.getsize(args.trace) < LAZY_BYTES:
            return None
    except OSError:
        return None
    return args.show


def cmd_replay(args) -> int:
    try:
        session = Session.load(
            args.trace,
            skip_bad=args.skip_bad,
            redact=args.redact,
            # --show N needs only the first N steps: time-to-first-view
            # stays flat however large the file is.
            max_steps=_lazy_limit(args),
        )
    except (ValueError, OSError) as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    color = _color_enabled() and not args.no_color
    if args.export_md:
        with open(args.export_md, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(export_markdown(session))
        print(f"wrote {args.export_md}")
        return 0
    if args.export_html:
        if not args.redact and not args.no_redact_html:
            session = Session.load(args.trace, skip_bad=args.skip_bad, redact=True)
        with open(args.export_html, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(render_html(session))
        note = "" if (args.redact or not args.no_redact_html) else " (NOT redacted)"
        print(f"wrote {args.export_html}{note}")
        return 0
    if args.list:
        print(render_list(session, color))
        return 0
    if args.show is not None:
        try:
            step = session.get_step(args.show)
        except IndexError as exc:
            print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
            return 2
        total: Any = "?" if session.partial else len(session.steps)
        print(render_step(step, total, color))
        return 0
    Repl(session, color).run(script=args.cmd)
    return 0


def _load_or_fail(args, **kw):
    try:
        return Session.load(args.trace, skip_bad=args.skip_bad, **kw)
    except (ValueError, OSError) as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return None


def cmd_why(args) -> int:
    session = _load_or_fail(args, redact=args.redact)
    if session is None:
        return 2
    try:
        exp = explain(session, args.step)
    except IndexError as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    if args.json:
        print(
            json.dumps(
                {
                    "step": exp.step,
                    "tool": exp.tool,
                    "ok": exp.ok,
                    "prompt": exp.prompt,
                    "model_text": exp.model_text,
                    "turn_steps": exp.turn_steps,
                    "next_steps": exp.next_steps,
                    "provenance": [vars(p) for p in exp.provenance],
                    "effects": [vars(e) for e in exp.effects],
                },
                indent=2,
                default=str,
            )
        )
        return 0
    print(render_explanation(exp, _color_enabled() and not args.no_color))
    return 0


def cmd_audit(args) -> int:
    session = _load_or_fail(args, redact=args.redact)
    if session is None:
        return 2
    findings = audit(session, check_secrets=not args.no_secrets)
    order = {"high": 0, "medium": 1, "low": 2}
    findings = [f for f in findings if order[f.severity] <= order[args.min_severity]]
    if args.json:
        print(json.dumps([f.to_dict() for f in findings], indent=2))
    else:
        color = _color_enabled() and not args.no_color
        if not findings:
            print(_c("audit: nothing suspicious found", GREEN, color))
        else:
            print(_c(f"audit: {len(findings)} finding(s) in {clean(session.path)}", BOLD, color))
            shown = findings[: args.limit] if args.limit > 0 else findings
            for f in shown:
                tint = RED if f.severity == "high" else YELLOW if f.severity == "medium" else DIM
                where = f"step {f.step}" if f.step else "session"
                print(
                    f"  {_c(f.severity.upper().ljust(6), tint, color)} "
                    f"{f.kind:<15} {where:<9} {clean(f.message)}"
                )
            if len(shown) < len(findings):
                print(_c(f"  … {len(findings) - len(shown)} more (use --limit 0)", DIM, color))
            print(_c("  leads, not verdicts: check with `redbg why TRACE N`", DIM, color))
    if args.strict and any(f.severity == "high" for f in findings):
        return 1
    return 0


def cmd_files(args) -> int:
    session = _load_or_fail(args, redact=args.redact)
    if session is None:
        return 2
    color = _color_enabled() and not args.no_color
    if args.json:
        ledger = file_ledger(session)
        print(json.dumps({p: [vars(e) for e in effs] for p, effs in ledger.items()}, indent=2))
        return 0
    print(render_ledger(session, color))
    return 0


def cmd_blame(args) -> int:
    session = _load_or_fail(args, redact=args.redact)
    if session is None:
        return 2
    print(render_blame(session, args.path, _color_enabled() and not args.no_color))
    return 0


def cmd_diff(args) -> int:
    try:
        a = Session.load(args.a, skip_bad=args.skip_bad)
        b = Session.load(args.b, skip_bad=args.skip_bad)
    except (ValueError, OSError) as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    ignore = _split_csv(args.ignore_keys)
    if args.json:
        print(json.dumps(diff_to_dict(a, b, ignore), indent=2, default=str))
        return 0
    color = _color_enabled() and not args.no_color
    print(render_diff(a, b, use_color=color, ignore_keys=ignore))
    return 0


def _split_csv(value) -> tuple[str, ...]:
    """Flatten repeatable, comma-separated option values."""
    if not value:
        return ()
    items = value if isinstance(value, list) else [value]
    return tuple(p.strip() for item in items for p in item.split(",") if p.strip())


def cmd_check(args) -> int:
    try:
        candidate = Session.load(args.trace, skip_bad=args.skip_bad)
        baseline = (
            Session.load(args.baseline, skip_bad=args.skip_bad)
            if args.baseline
            else None
        )
        fail_on = _split_csv(args.fail_on)
        rules = CheckRules(
            require_complete=not args.allow_incomplete,
            max_steps=args.max_steps,
            max_failures=args.max_failures,
            forbid_tools=list(_split_csv(args.forbid_tool)),
            require_tools=list(_split_csv(args.require_tool)),
            max_repeats=args.max_repeats,
            max_cycles=args.max_cycles,
            max_tokens=args.max_tokens,
            forbid_paths=list(_split_csv(args.forbid_path)),
            forbid_writes=list(_split_csv(args.forbid_write)),
            forbid_args=list(args.forbid_arg or []),
            ignore_keys=_split_csv(args.ignore_keys),
            allow_empty=args.allow_empty,
            **({"fail_on": fail_on} if fail_on else {}),
        )
    except (ValueError, OSError) as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    result = run_check(candidate, rules, baseline)
    if args.junit:
        try:
            with open(args.junit, "w", encoding="utf-8", newline="\n") as handle:
                handle.write(to_junit(result))
        except OSError as exc:
            print(f"redbg: --junit report not written: {_why_failed(exc)}", file=sys.stderr)
            return 2
    if args.github:
        print(to_github(result, args.limit))
        return 0 if result.passed else 1
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, default=str))
        return 0 if result.passed else 1
    color = _color_enabled() and not args.no_color
    target = clean(result.candidate)
    if result.baseline:
        target += f" vs baseline {clean(result.baseline)}"
    checked = ", ".join(result.checked) or "nothing"
    if result.passed:
        print(_c(f"✓ check passed: {target}", GREEN, color))
        print(_c(f"  rules: {checked}", DIM, color))
        return 0
    print(_c(f"✗ check FAILED: {target}", RED + BOLD, color))
    shown = result.violations[: args.limit] if args.limit > 0 else result.violations
    for v in shown:
        print(f"  [{v.rule}] {clean(v.message)}")
    hidden = len(result.violations) - len(shown)
    if hidden > 0:
        print(_c(f"  … {hidden} more (use --limit 0 to show all)", DIM, color))
    print(_c(f"  rules: {checked}", DIM, color))
    return 1


def _load_tools_module(path: str) -> tuple[dict, object]:
    try:
        namespace = runpy.run_path(path)
    except (OSError, ValueError):
        raise
    except BaseException as exc:  # noqa: BLE001 - your file's own error, shown plainly
        if isinstance(exc, KeyboardInterrupt):
            raise
        raise ValueError(
            f"{path} failed while loading: {type(exc).__name__}: {exc}"
        ) from None
    tools = namespace.get("TOOLS", {})
    if not isinstance(tools, dict):
        raise ValueError(f"{path}: TOOLS must be a dict of name -> callable")
    return tools, namespace.get("MODEL")


def cmd_fork(args) -> int:
    try:
        if args.save:
            # The fork would otherwise silently replace the original trace.
            ensure_distinct(args.trace, args.save)
        session = Session.load(args.trace, skip_bad=args.skip_bad)
    except (ValueError, OSError) as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    override_args = None
    if args.override_args:
        try:
            override_args = json.loads(args.override_args)
        except json.JSONDecodeError as exc:
            print(f"redbg: bad --override-args JSON: {exc}", file=sys.stderr)
            return 2
    tool_impls: dict = {}
    model_fn: Any = None
    if args.tools:
        try:
            tool_impls, model_fn = _load_tools_module(args.tools)
        except (OSError, ValueError) as exc:
            print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
            return 2
    spec = ForkSpec(
        at_step=args.at,
        strategy=args.strategy,
        override_args=override_args,
        inject_prompt=args.inject,
        tool_impls=tool_impls,
        model_fn=model_fn,
        max_steps=args.max_steps,
    )
    try:
        forked = fork_session(session, spec)
    except ValueError as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    if args.save:
        forked.save(args.save)
        print(f"forked {forked.steps} steps ({spec.strategy}) -> {args.save}")
    else:
        # Print a compact step list of the fork to stdout.
        for event in forked.events:
            if event.get("type") == "tool_call":
                print(
                    clean(
                        f"step {event['step']}: {event['tool']} "
                        f"{json.dumps(event.get('args', {}), default=str)[:100]}"
                    )
                )
    return 0


def _value_res(args):
    return DEFAULT_VALUE_RES + (PII_VALUE_RES if getattr(args, "pii", False) else [])


def cmd_redact(args) -> int:
    try:
        stats = redact_file(args.src, args.dst, value_res=_value_res(args))
    except (ValueError, OSError) as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    print(
        f"redacted {stats['redactions']} value(s) across "
        f"{stats['events']} events -> {stats['dst']}"
    )
    return 0


def cmd_scan(args) -> int:
    try:
        findings = scan_file(args.trace, value_res=_value_res(args))
    except (ValueError, OSError) as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    if not findings:
        print("scan clean: no likely secrets found.")
        return 0
    print(f"found {len(findings)} suspicious value(s):")
    for finding in findings:
        print(
            clean(
                f"  line {finding.line_no} [{finding.field}]: "
                f"{finding.preview} ({finding.reason})"
            )
        )
    print("hint: run `redbg redact` before sharing this trace.")
    return 1


def info_to_dict(session: Session) -> dict:
    tools: dict[str, int] = {}
    failed = 0
    total_ms = 0.0
    for step in session.steps:
        tools[step.tool] = tools.get(step.tool, 0) + 1
        failed += step.ok is False
        total_ms += step.duration_ms or 0.0
    return {
        "path": session.path,
        "format": session.format,
        "agent": session.agent,
        "session_id": session.session_id,
        "status": session.status,
        "steps": len(session.steps),
        "failed": failed,
        "tool_time_ms": total_ms,
        "prompts": len(session.prompts),
        "responses": len(session.responses),
        "tools": tools,
        "usage": session.usage or None,
        "repeats": [vars(r) for r in find_repeats(session)],
        "cycles": [vars(c) for c in find_cycles(session)],
    }


def cmd_info(args) -> int:
    try:
        session = Session.load(args.trace, skip_bad=args.skip_bad)
    except (ValueError, OSError) as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(info_to_dict(session), indent=2, default=str))
        return 0
    print(render_info(session, _color_enabled() and not args.no_color))
    return 0


def cmd_import(args) -> int:
    try:
        stats = import_file(args.src, args.dst, redact=args.redact)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    print(
        f"imported {stats['steps']} tool steps "
        f"({stats['events']} events) -> {stats['dst']}"
    )
    if stats.get("format") in (None, "otel"):
        print("note: OTel import is heuristic and lossy; verify with `redbg info`.")
    else:
        print(f"read as {stats['format']}; outputs over 20000 chars are cut (sha256 kept).")
    return 0


# ---------------------------------------------------------------------------
# demo / sessions
# ---------------------------------------------------------------------------

DEMO_FILES = ("sample-a.jsonl", "sample-b.jsonl")


def cmd_demo(args) -> int:
    """Write two small example traces so a pip user can try redbg in seconds."""
    import importlib.resources as resources

    dest = args.dir
    try:
        os.makedirs(dest, exist_ok=True)
        existing = [n for n in DEMO_FILES if os.path.exists(os.path.join(dest, n))]
        if existing and not args.force:
            print(
                f"redbg: {', '.join(existing)} already exist in {dest!r}; "
                "use --force to overwrite or pick another folder",
                file=sys.stderr,
            )
            return 2
        for name in DEMO_FILES:
            data = (resources.files("redbg") / "_samples" / name).read_bytes()
            with open(os.path.join(dest, name), "wb") as out:
                out.write(data)
    except OSError as exc:
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    a = os.path.join(dest, DEMO_FILES[0])
    b = os.path.join(dest, DEMO_FILES[1])

    def q(x: str) -> str:
        return f'"{x}"' if " " in x else x

    print(f"wrote two example traces to {dest}")
    print("try:")
    print(f"  redbg diff {q(a)} {q(b)}")
    print(f"  redbg check {q(b)} --baseline {q(a)}   (exits 1: the runs differ)")
    print(f"  redbg audit {q(b)}")
    print(f"  redbg replay {q(a)}")
    return 0


def _default_session_dirs() -> list[str]:
    home = os.path.expanduser("~")
    return [
        os.path.join(home, ".claude", "projects"),
        os.path.join(home, ".codex", "sessions"),
    ]


def _human_age(seconds: float) -> str:
    seconds = max(0, int(seconds))
    for unit, size in (("d", 86400), ("h", 3600), ("m", 60)):
        if seconds >= size:
            return f"{seconds // size}{unit} ago"
    return f"{seconds}s ago"


def cmd_sessions(args) -> int:
    """List recent agent transcripts (newest first) so you can pass one to redbg."""
    import time

    dirs = args.dir or _default_session_dirs()
    found: list[tuple[float, int, str]] = []
    scanned = 0
    for root in dirs:
        for folder, _subdirs, files in os.walk(root):  # never follows symlinked dirs
            for name in files:
                if not (name.endswith(".jsonl") or name.endswith(".jsonl.gz")):
                    continue
                scanned += 1
                if scanned > 50000:
                    break
                path = os.path.join(folder, name)
                try:
                    st = os.stat(path)
                except OSError:
                    continue
                found.append((st.st_mtime, st.st_size, path))
    if not found:
        shown = ", ".join(dirs)
        print(
            f"no transcripts found in: {shown}\n"
            "pass --dir FOLDER to look somewhere else",
            file=sys.stderr,
        )
        return 2
    found.sort(reverse=True)
    now = time.time()
    limit = args.limit if args.limit > 0 else len(found)
    if args.json:
        rows = [
            {"path": path, "bytes": size, "modified": mtime}
            for mtime, size, path in found[:limit]
        ]
        print(json.dumps(rows, indent=2))
        return 0
    for mtime, size, path in found[:limit]:
        print(f"{_human_age(now - mtime):>9}  {size / 1e6:8.2f} MB  {clean(path)}")
    if len(found) > limit:
        print(f"... {len(found) - limit} more (use --limit 0 for all)")
    print("open one with: redbg audit PATH   or   redbg replay PATH")
    return 0


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------


def _add_common(parser) -> None:
    parser.add_argument(
        "--skip-bad",
        action="store_true",
        help="skip malformed lines instead of failing",
    )
    parser.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    parser.add_argument(
        "--redact",
        action="store_true",
        help="redact secrets from everything shown (nothing is written)",
    )


_PII_HELP = "also treat e-mail addresses and Luhn-valid card numbers as sensitive"


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redbg",
        description="gdb for agent sessions.",
        epilog=(
            "new here? run `redbg demo` to get two example traces.\n"
            "exit codes: 0 ok, 1 problems found (check/scan/audit --strict), "
            "2 could not run (bad input, bad option, unwritable output), "
            "141 output pipe closed, 130 interrupted"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("demo", help="write two example traces to try redbg on")
    p.add_argument("dir", nargs="?", default="redbg-demo", help="folder (default: redbg-demo)")
    p.add_argument("--force", action="store_true", help="overwrite existing example files")
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser(
        "sessions", help="list recent Claude Code / Codex transcripts on this machine"
    )
    p.add_argument(
        "--dir", action="append", metavar="FOLDER",
        help="folder to search (repeatable; default: ~/.claude/projects and ~/.codex/sessions)",
    )
    p.add_argument("--limit", type=int, default=15, help="rows to show (0 = all)")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_sessions)

    p = sub.add_parser("replay", help="step through a session like a debugger")
    p.add_argument("trace")
    p.add_argument("--list", action="store_true", help="list steps and exit")
    p.add_argument("--show", type=int, metavar="N", help="show step N and exit")
    p.add_argument(
        "--cmd", metavar="CMDS", help="run ';'-separated REPL commands and exit"
    )
    p.add_argument(
        "--export-md", metavar="FILE", help="write a Markdown report and exit"
    )
    p.add_argument(
        "--export-html",
        metavar="FILE",
        help="write a self-contained, script-free HTML report (redacted by default)",
    )
    p.add_argument(
        "--no-redact-html",
        action="store_true",
        help="do not redact the HTML report (not safe to share)",
    )
    _add_common(p)
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("diff", help="diff two sessions, find the divergence")
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument(
        "--ignore-keys",
        action="append",
        metavar="K1,K2",
        help="arg keys to ignore when comparing (any depth); repeatable",
    )
    _add_common(p)
    p.set_defaults(func=cmd_diff)

    p = sub.add_parser(
        "check",
        help="CI gate: fail (exit 1) on regressions vs a baseline or rule breaks",
        description="Exit 0 = pass, 1 = violations, 2 = could not run. By "
        "default the session must have finished with status ok, every step "
        "must have a result (disable with --allow-incomplete), and the trace "
        "must contain at least one tool step (disable with --allow-empty).",
    )
    p.add_argument("trace", help="candidate session to check")
    p.add_argument(
        "--baseline", metavar="TRACE", help="known-good session to compare against"
    )
    p.add_argument(
        "--fail-on",
        action="append",
        metavar="KINDS",
        help="baseline diff kinds that fail the check (default: all changes). "
        "choices: " + ",".join(FAIL_ON_CHOICES),
    )
    p.add_argument("--ignore-keys", action="append", metavar="K1,K2")
    p.add_argument("--max-steps", type=int, metavar="N")
    p.add_argument("--max-failures", type=int, metavar="N")
    p.add_argument(
        "--max-repeats",
        type=int,
        metavar="N",
        help="fail if any tool is called more than N times in a row "
        "with identical args (loop detector)",
    )
    p.add_argument(
        "--max-tokens",
        type=int,
        metavar="N",
        help="fail if the session used more than N tokens (input + output + "
        "cache read + cache creation; counts, not cost); needs usage data",
    )
    p.add_argument(
        "--max-cycles",
        type=int,
        metavar="N",
        help="fail if an alternating pattern of 2-8 calls (a,b,a,b...) repeats "
        "more than N times",
    )
    p.add_argument(
        "--forbid-path",
        action="append",
        metavar="GLOB",
        help="fail if a step reads, writes or deletes a matching file "
        "(e.g. '.env', '*/secrets/*'); repeatable",
    )
    p.add_argument(
        "--forbid-write",
        action="append",
        metavar="GLOB",
        help="like --forbid-path but only writes and deletes count; repeatable",
    )
    p.add_argument(
        "--forbid-arg",
        action="append",
        metavar="REGEX",
        help="fail if a call's tool name or arguments match (case-insensitive), "
        "e.g. 'rm\\s+-rf' or 'git push.*--force'; repeatable (commas are "
        "kept: one pattern per flag)",
    )
    p.add_argument(
        "--forbid-tool",
        action="append",
        metavar="GLOB",
        help="fail if any call matches (e.g. 'delete_*'); repeatable",
    )
    p.add_argument(
        "--require-tool",
        action="append",
        metavar="GLOB",
        help="fail unless some call matches; repeatable",
    )
    p.add_argument("--allow-incomplete", action="store_true")
    p.add_argument(
        "--allow-empty",
        action="store_true",
        help="accept a trace with zero tool steps / a check with no rules",
    )
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.add_argument(
        "--github",
        action="store_true",
        help="print GitHub Actions ::error annotations instead of the text report",
    )
    p.add_argument(
        "--junit",
        metavar="FILE",
        help="also write a JUnit XML report (one test case per rule) to FILE",
    )
    p.add_argument(
        "--limit", type=int, default=50, help="max violations to print (0 = all)"
    )
    _add_common(p)
    p.set_defaults(func=cmd_check)

    p = sub.add_parser("fork", help="re-run a session tail with new input")
    p.add_argument("trace")
    p.add_argument(
        "--at",
        type=int,
        required=True,
        help="fork at step N (history = steps before N)",
    )
    p.add_argument(
        "--strategy",
        choices=["playback", "live"],
        default="playback",
        help="playback: replay recorded model text (default); "
        "live: call --tools MODEL for real",
    )
    p.add_argument(
        "--override-args",
        metavar="JSON",
        help="replace args of the first tool call after the fork",
    )
    p.add_argument(
        "--inject", metavar="TEXT", help="insert a user message at the fork point"
    )
    p.add_argument(
        "--tools",
        metavar="TOOLS.PY",
        help="python file defining TOOLS dict and optional MODEL",
    )
    p.add_argument("--max-steps", type=int, default=50)
    p.add_argument("--save", metavar="FILE", help="write forked trace here")
    _add_common(p)
    p.set_defaults(func=cmd_fork)

    p = sub.add_parser("redact", help="strip secrets from a trace")
    p.add_argument("src")
    p.add_argument("-o", "--dst", required=True)
    p.add_argument("--pii", action="store_true", help=_PII_HELP)
    _add_common(p)
    p.set_defaults(func=cmd_redact)

    p = sub.add_parser("scan", help="audit a trace for likely secrets")
    p.add_argument("trace")
    p.add_argument("--pii", action="store_true", help=_PII_HELP)
    _add_common(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("info", help="summarize a session")
    p.add_argument("trace")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    _add_common(p)
    p.set_defaults(func=cmd_info)

    p = sub.add_parser(
        "import",
        help="convert Claude Code / Codex / message-array / OTel logs to redbg",
    )
    p.add_argument("src")
    p.add_argument("-o", "--dst", required=True)
    _add_common(p)
    p.set_defaults(func=cmd_import)

    p = sub.add_parser("why", help="why did the agent make call N?")
    p.add_argument("trace")
    p.add_argument("step", type=int)
    p.add_argument("--json", action="store_true")
    _add_common(p)
    p.set_defaults(func=cmd_why)

    p = sub.add_parser(
        "audit",
        help="rank the suspicious steps: invented paths, destructive commands, loops",
    )
    p.add_argument("trace")
    p.add_argument("--json", action="store_true")
    p.add_argument(
        "--min-severity", choices=["high", "medium", "low"], default="low",
        help="hide findings below this severity",
    )
    p.add_argument("--limit", type=int, default=50, help="max findings (0 = all)")
    p.add_argument("--no-secrets", action="store_true", help="skip the credential scan")
    p.add_argument("--strict", action="store_true", help="exit 1 if any high finding")
    _add_common(p)
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("files", help="files each step read / wrote / deleted")
    p.add_argument("trace")
    p.add_argument("--json", action="store_true")
    _add_common(p)
    p.set_defaults(func=cmd_files)

    p = sub.add_parser("blame", help="which steps touched PATH")
    p.add_argument("trace")
    p.add_argument("path")
    _add_common(p)
    p.set_defaults(func=cmd_blame)

    return parser


def _materialize_stdin(args) -> None:
    """Replace a ``-`` trace argument with a temp copy of standard input.

    Traces are read more than once (format sniffing, then loading), so a
    pipe has to be spooled to a file first. The copy lives in a private
    temp directory and is removed at exit.
    """
    names = [n for n in ("trace", "a", "b", "baseline", "src") if getattr(args, n, None) == "-"]
    if not names:
        return
    if len(names) > 1:
        raise ValueError("only one input can be read from standard input ('-')")
    tmp = tempfile.mkdtemp(prefix="redbg-stdin-")
    atexit.register(shutil.rmtree, tmp, True)
    path = os.path.join(tmp, "stdin")
    with open(path, "wb") as out:
        shutil.copyfileobj(sys.stdin.buffer, out)
    setattr(args, names[0], path)


def _safe_streams() -> None:
    """Never crash because the console cannot show a character.

    A Windows pipe/redirect is often cp1252 and a minimal Linux container is
    often ASCII; the report symbols and any non-Latin trace text would raise
    ``UnicodeEncodeError`` (a traceback and exit 1, which CI reads as "rule
    violations"). Unencodable characters are printed as ``\\uXXXX`` instead.
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            if (stream.encoding or "").lower().replace("_", "-") not in ("utf-8", "utf8"):
                stream.reconfigure(errors="backslashreplace")  # type: ignore[union-attr]
        except (AttributeError, ValueError, OSError):
            pass


def main(argv: list[str] | None = None) -> int:
    _safe_streams()
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        _materialize_stdin(args)
        return args.func(args)
    except ValueError as exc:
        if "standard input" not in str(exc):
            return _internal_error(exc)
        print(f"redbg: {exc}", file=sys.stderr)
        return 2
    except BrokenPipeError:
        # `redbg ... | head`: the reader left. Point stdout at devnull so the
        # interpreter's exit-time flush doesn't raise again, and exit with the
        # conventional SIGPIPE status (never 0/1/2, which mean pass/violations/
        # could-not-run).
        try:
            os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
        except (OSError, ValueError):
            pass
        return 141
    except RecursionError:
        # A pathologically nested trace (or tool result) — "could not run",
        # never a traceback and never exit 1 (which means "violations").
        print(
            "redbg: input is nested too deeply to process "
            "(raise sys.setrecursionlimit or flatten the data)",
            file=sys.stderr,
        )
        return 2
    except KeyboardInterrupt:
        print("redbg: interrupted", file=sys.stderr)
        return 130
    except OSError as exc:
        # Any file problem not handled closer to the command (unwritable
        # output, folder given as a trace, disk full): say so plainly.
        print(f"redbg: {_why_failed(exc)}", file=sys.stderr)
        return 2
    except MemoryError:
        print("redbg: ran out of memory reading this input", file=sys.stderr)
        return 2
    except Exception as exc:  # noqa: BLE001 - last resort, see _internal_error
        return _internal_error(exc)


def _internal_error(exc: BaseException) -> int:
    """Report a bug as a one-liner with exit 2, never a traceback with exit 1.

    Exit 1 means "the check found problems"; a crash must not look like that.
    ``REDBG_DEBUG=1`` restores the full traceback.
    """
    if os.environ.get("REDBG_DEBUG"):
        raise exc
    print(
        f"redbg: unexpected {type(exc).__name__}: {exc}\n"
        "  this is a bug in redbg or a trace it could not handle; set "
        "REDBG_DEBUG=1 for the full traceback and please report it at "
        "https://github.com/calasdan-sketch/redbg/issues",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    sys.exit(main())
