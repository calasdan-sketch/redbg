"""redbg command-line interface.

Subcommands:
  replay TRACE        interactive debugger REPL (step next/prev, inspect)
  diff A B            side-by-side divergence report for two sessions
  check TRACE         CI gate: regressions vs --baseline, budgets, loops
  fork TRACE --at N   re-run the tail of a session with modified input
  redact SRC -o DST   strip secrets from a trace
  scan TRACE          audit a trace for likely secrets (exit 1 if found)
  info TRACE          session summary
  import SRC -o DST   convert Claude Code / Codex / chat-message / OTel logs
  why TRACE N         why did the agent make call N? (causal chain)
  files TRACE         which files each step read / wrote / deleted
  blame TRACE PATH    which steps touched PATH

Every command opens redbg traces, Claude Code transcripts, Codex rollouts and
OpenAI/Anthropic message logs directly (format auto-detected).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import runpy
import sys

from . import __version__
from ._text import clean, md_fence
from .analysis import Breakpoint, blame, explain, file_ledger, run_to_breakpoint
from .check import FAIL_ON_CHOICES, CheckRules, run_check
from .diff import diff_to_dict, find_repeats, render_diff
from .fork import ForkSpec, fork_session
from .htmlexport import render_html
from .importer import import_file
from .redact import redact_file, scan_file
from .replay import Navigator, Session, ensure_distinct

BOLD = "\033[1m"
DIM = "\033[2m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RESET = "\033[0m"


def _color_enabled() -> bool:
    return sys.stdout.isatty() and os.environ.get("NO_COLOR", "") == ""


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
        print(f"redbg: {exc}", file=sys.stderr)
        return 2
    color = _color_enabled() and not args.no_color
    if args.export_md:
        with open(args.export_md, "w", encoding="utf-8") as handle:
            handle.write(export_markdown(session))
        print(f"wrote {args.export_md}")
        return 0
    if args.export_html:
        if not args.redact and not args.no_redact_html:
            session = Session.load(args.trace, skip_bad=args.skip_bad, redact=True)
        with open(args.export_html, "w", encoding="utf-8") as handle:
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
            print(f"redbg: {exc}", file=sys.stderr)
            return 2
        print(render_step(step, "?" if session.partial else len(session.steps), color))
        return 0
    Repl(session, color).run(script=args.cmd)
    return 0


def _load_or_fail(args, **kw):
    try:
        return Session.load(args.trace, skip_bad=args.skip_bad, **kw)
    except (ValueError, OSError) as exc:
        print(f"redbg: {exc}", file=sys.stderr)
        return None


def cmd_why(args) -> int:
    session = _load_or_fail(args, redact=args.redact)
    if session is None:
        return 2
    try:
        exp = explain(session, args.step)
    except IndexError as exc:
        print(f"redbg: {exc}", file=sys.stderr)
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
        print(f"redbg: {exc}", file=sys.stderr)
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
            ignore_keys=_split_csv(args.ignore_keys),
            allow_empty=args.allow_empty,
            **({"fail_on": fail_on} if fail_on else {}),
        )
    except (ValueError, OSError) as exc:
        print(f"redbg: {exc}", file=sys.stderr)
        return 2
    result = run_check(candidate, rules, baseline)
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
    namespace = runpy.run_path(path)
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
        print(f"redbg: {exc}", file=sys.stderr)
        return 2
    override_args = None
    if args.override_args:
        try:
            override_args = json.loads(args.override_args)
        except json.JSONDecodeError as exc:
            print(f"redbg: bad --override-args JSON: {exc}", file=sys.stderr)
            return 2
    tool_impls: dict = {}
    model_fn = None
    if args.tools:
        try:
            tool_impls, model_fn = _load_tools_module(args.tools)
        except (OSError, ValueError) as exc:
            print(f"redbg: {exc}", file=sys.stderr)
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
        print(f"redbg: {exc}", file=sys.stderr)
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


def cmd_redact(args) -> int:
    try:
        stats = redact_file(args.src, args.dst)
    except (ValueError, OSError) as exc:
        print(f"redbg: {exc}", file=sys.stderr)
        return 2
    print(
        f"redacted {stats['redactions']} value(s) across "
        f"{stats['events']} events -> {stats['dst']}"
    )
    return 0


def cmd_scan(args) -> int:
    try:
        findings = scan_file(args.trace)
    except (ValueError, OSError) as exc:
        print(f"redbg: {exc}", file=sys.stderr)
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


def cmd_info(args) -> int:
    try:
        session = Session.load(args.trace, skip_bad=args.skip_bad)
    except (ValueError, OSError) as exc:
        print(f"redbg: {exc}", file=sys.stderr)
        return 2
    print(render_info(session, _color_enabled() and not args.no_color))
    return 0


def cmd_import(args) -> int:
    try:
        stats = import_file(args.src, args.dst, redact=args.redact)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"redbg: {exc}", file=sys.stderr)
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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="redbg", description="gdb for agent sessions."
    )
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )
    sub = parser.add_subparsers(dest="command", required=True)

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
    _add_common(p)
    p.set_defaults(func=cmd_redact)

    p = sub.add_parser("scan", help="audit a trace for likely secrets")
    p.add_argument("trace")
    _add_common(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("info", help="summarize a session")
    p.add_argument("trace")
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


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except RecursionError:
        # A pathologically nested trace (or tool result) — "could not run",
        # never a traceback and never exit 1 (which means "violations").
        print(
            "redbg: input is nested too deeply to process "
            "(raise sys.setrecursionlimit or flatten the data)",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    sys.exit(main())
