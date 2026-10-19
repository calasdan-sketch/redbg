"""redbg command-line interface.

Subcommands:
  replay TRACE        interactive debugger REPL (step next/prev, inspect)
  diff A B            side-by-side divergence report for two sessions
  fork TRACE --at N   re-run the tail of a session with modified input
  redact SRC -o DST   strip secrets from a trace
  scan TRACE          audit a trace for likely secrets (exit 1 if found)
  info TRACE          session summary
  import SRC -o DST   convert OTel/Langfuse-shaped traces to redbg format
"""

from __future__ import annotations

import argparse
import json
import os
import runpy
import sys

from . import __version__
from .diff import render_diff
from .fork import ForkSpec, fork_session
from .importer import import_file
from .redact import redact_file, scan_file
from .replay import Navigator, Session

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
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n…[{len(text) - limit} more chars]"


def render_step(step, total: int, color: bool, show_context: bool = True) -> str:
    """Render one step the way `s` shows it in the REPL."""
    status = "ok" if step.ok else ("FAIL" if step.ok is False else "no result")
    status_c = _c(status, GREEN if step.ok else RED, color)
    lines = [
        _c(
            f"── step {step.n}/{total} · {step.tool} · {status_c} · "
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
        lines.append(f"{step.n:>4} {mark} {_fmt_ms(step.duration_ms):>10}  {step.tool}")
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
        _c(f"session: {session.path}", BOLD, color),
        f"  agent:      {session.agent}",
        f"  session id: {session.session_id}",
        f"  status:     {session.status}",
        f"  steps:      {len(session.steps)}",
        f"  failed:     {failed}",
        f"  tool time:  {_fmt_ms(total_ms)}",
        f"  prompts:    {len(session.prompts)}",
        f"  responses:  {len(session.responses)}",
        "  tools:      "
        + ", ".join(f"{name}×{count}" for name, count in sorted(tools.items())),
    ]
    return "\n".join(lines)


def export_markdown(session: Session) -> str:
    lines = [
        f"# redbg session: `{session.path}`",
        "",
        f"- agent: {session.agent}",
        f"- session id: {session.session_id}",
        f"- status: {session.status}",
        f"- steps: {len(session.steps)}",
        "",
    ]
    for step in session.steps:
        status = "ok" if step.ok else "FAIL"
        lines.append(
            f"## step {step.n}: `{step.tool}` ({status}, {_fmt_ms(step.duration_ms)})"
        )
        lines.append("")
        lines.append("```json")
        lines.append(
            json.dumps(
                step.args, indent=2, sort_keys=True, default=str, ensure_ascii=False
            )
        )
        lines.append("```")
        if step.output:
            lines.append("")
            lines.append("<details><summary>output</summary>")
            lines.append("")
            lines.append("```")
            lines.append(_truncate(step.output, 4000))
            lines.append("```")
            lines.append("</details>")
        if step.error:
            lines.append("")
            lines.append(f"**error:** {step.error}")
        lines.append("")
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
            print(render_info(self.session, self.color))
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


def cmd_replay(args) -> int:
    try:
        session = Session.load(args.trace, skip_bad=args.skip_bad)
    except (ValueError, OSError) as exc:
        print(f"redbg: {exc}", file=sys.stderr)
        return 2
    color = _color_enabled() and not args.no_color
    if args.export_md:
        with open(args.export_md, "w", encoding="utf-8") as handle:
            handle.write(export_markdown(session))
        print(f"wrote {args.export_md}")
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
        print(render_step(step, len(session.steps), color))
        return 0
    Repl(session, color).run(script=args.cmd)
    return 0


def cmd_diff(args) -> int:
    try:
        a = Session.load(args.a, skip_bad=args.skip_bad)
        b = Session.load(args.b, skip_bad=args.skip_bad)
    except (ValueError, OSError) as exc:
        print(f"redbg: {exc}", file=sys.stderr)
        return 2
    color = _color_enabled() and not args.no_color
    print(render_diff(a, b, use_color=color))
    return 0


def _load_tools_module(path: str) -> tuple[dict, object]:
    namespace = runpy.run_path(path)
    tools = namespace.get("TOOLS", {})
    if not isinstance(tools, dict):
        raise ValueError(f"{path}: TOOLS must be a dict of name -> callable")
    return tools, namespace.get("MODEL")


def cmd_fork(args) -> int:
    try:
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
                    f"step {event['step']}: {event['tool']} "
                    f"{json.dumps(event.get('args', {}), default=str)[:100]}"
                )
    return 0


def cmd_redact(args) -> int:
    stats = redact_file(args.src, args.dst)
    print(
        f"redacted {stats['redactions']} value(s) across "
        f"{stats['events']} events -> {stats['dst']}"
    )
    return 0


def cmd_scan(args) -> int:
    findings = scan_file(args.trace)
    if not findings:
        print("scan clean: no likely secrets found.")
        return 0
    print(f"found {len(findings)} suspicious value(s):")
    for finding in findings:
        print(
            f"  line {finding.line_no} [{finding.field}]: "
            f"{finding.preview} ({finding.reason})"
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
        stats = import_file(args.src, args.dst)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"redbg: {exc}", file=sys.stderr)
        return 2
    print(
        f"imported {stats['steps']} tool steps "
        f"({stats['events']} events) -> {stats['dst']}"
    )
    print("note: import is heuristic and lossy; verify the result with `redbg info`.")
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
    _add_common(p)
    p.set_defaults(func=cmd_replay)

    p = sub.add_parser("diff", help="diff two sessions, find the divergence")
    p.add_argument("a")
    p.add_argument("b")
    _add_common(p)
    p.set_defaults(func=cmd_diff)

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

    p = sub.add_parser("import", help="convert OTel/Langfuse traces to redbg")
    p.add_argument("src")
    p.add_argument("-o", "--dst", required=True)
    _add_common(p)
    p.set_defaults(func=cmd_import)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
