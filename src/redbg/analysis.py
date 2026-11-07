"""Root-cause tools: what did each step touch, and why did the agent do it?

Three questions an incident responder asks of an agent transcript:

* ``effects`` / ``file_ledger`` - which files did this step read, write,
  delete? (``redbg files``, ``redbg blame``)
* ``explain`` - why was this call made? The user prompt and model text it
  followed, the calls that came before it in the same turn, and for every
  concrete value in its arguments, *where that value first appeared*
  (a prompt, an earlier tool output) - or that it appeared nowhere, which
  is the signature of an invented path, URL or identifier.
* ``Breakpoint`` - stop the replay on a tool glob, a failure, a regex, or
  a file touch.

Honesty about confidence: edit tools that name a file (Write, Edit,
apply_patch, ...) give *declared* effects. Shell commands are parsed
conservatively (redirects, ``tee``, ``sed -i``, ``rm``, ``mv``, ``cp``,
``touch``) and are marked *inferred*; a script that writes files from
inside Python or Make is invisible to this analysis, and the output says
so rather than implying completeness.
"""

from __future__ import annotations

import fnmatch
import json
import posixpath
import re
import shlex
from dataclasses import dataclass, field

from ._text import canonical_name

READ_TOOLS = frozenset(
    "read view cat read_file open_file notebookread get_file_contents".split()
)
WRITE_TOOLS = frozenset(
    "write edit multiedit notebookedit write_file create_file edit_file "
    "str_replace str_replace_editor str_replace_based_edit_tool replace "
    "insert apply_edit".split()
)
SHELL_TOOLS = frozenset("bash shell exec run run_command execute local_shell".split())
PATCH_TOOLS = frozenset("apply_patch applypatch patch".split())
_PATH_KEYS = (
    "file_path", "path", "filepath", "filename", "file", "notebook_path", "target_file",
)
_PATCH_RE = re.compile(r"^\*\*\* (Add|Update|Delete) File:\s*(.+?)\s*$", re.M)
_PATCH_MOVE_RE = re.compile(r"^\*\*\* Move to:\s*(.+?)\s*$", re.M)


@dataclass(frozen=True)
class Effect:
    step: int
    kind: str  # read | write | delete
    path: str
    how: str  # declared | inferred
    tool: str
    ok: bool | None


_WIN_PATH_RE = re.compile(r"^(?:[A-Za-z]:[\\/]|\\\\[^\\/])")


def _is_windows_path(path: str) -> bool:
    return bool(_WIN_PATH_RE.match(path)) or (
        "\\" in path and "/" not in path
    )


def _norm_path(path: str) -> str:
    path = path.strip().strip("\"'")
    if _is_windows_path(path):
        path = path.replace("\\", "/")
        if re.match(r"^[A-Za-z]:", path):
            path = path[0].upper() + path[1:]  # drive letters are case-insensitive
    path = posixpath.normpath(path) if path else path
    return path


def _first_str(args: dict, keys) -> str | None:
    for key in keys:
        value = args.get(key)
        if isinstance(value, str) and value.strip():
            return value
    return None


_PS_DELETE = frozenset("remove-item ri del erase rd rmdir rm".split())
_PS_WRITE_FIRST = frozenset(
    "set-content add-content out-file new-item ni sc ac".split()
)
_PS_READ = frozenset("get-content gc type cat".split())
_PS_COPY = frozenset("copy-item copy cp".split())
_PS_MOVE = frozenset("move-item move mv".split())
_OUTPUT_FLAGS = {"curl": ("-o", "--output"), "wget": ("-o", "-O", "--output-document")}


def _shell_effects(command: str) -> list[tuple[str, str]]:
    """Conservative (kind, path) pairs from a shell command string.

    Understands POSIX shells and the common cmd.exe / PowerShell verbs.
    Windows-looking commands (a drive letter or UNC path) are read with
    backslashes treated as path separators, not escapes.
    """
    out: list[tuple[str, str]] = []
    if not isinstance(command, str) or len(command) > 20_000:
        return out
    # split on control operators so each simple command is analysed alone
    for part in re.split(r"&&|\|\||;|\n|\|(?!\|)", command):
        if re.search(r"(?:^|[\s\"'=(])[A-Za-z]:\\|\\\\[A-Za-z0-9_.$-]", part):
            part = part.replace("\\", "/")
        try:
            toks = shlex.split(part, posix=True)
        except ValueError:
            toks = part.split()
        if not toks:
            continue
        i = 0
        args = []
        while i < len(toks):
            t = toks[i]
            m = re.fullmatch(r"(?:\d?>>?|&>>?)(.*)", t)
            if m:
                target = m.group(1) or (toks[i + 1] if i + 1 < len(toks) else "")
                if target and not target.startswith("&") and target != "/dev/null":
                    out.append(("write", target))
                i += 1 if m.group(1) else 2  # skip the operator and its target
                continue
            args.append(t)
            i += 1
        # drop leading env assignments and sudo
        while args and (re.match(r"^\w+=", args[0]) or args[0] in ("sudo", "time")):
            args = args[1:]
        if not args:
            continue
        cmd = posixpath.basename(args[0]).lower()
        if cmd.endswith(".exe"):
            cmd = cmd[:-4]
        if cmd == "git" and len(args) > 1:
            sub = args[1].lower()
            grest = [a for a in args[2:] if not a.startswith("-") and a != "--"]
            if sub == "rm":
                out += [("delete", a) for a in grest]
            elif sub == "mv" and len(grest) >= 2:
                out += [("delete", a) for a in grest[:-1]] + [("write", grest[-1])]
            elif sub in ("restore", "checkout") and "--" in args:
                out += [("write", a) for a in args[args.index("--") + 1 :]]
            elif sub == "add":
                out += [("read", a) for a in grest]
            continue
        flags = _OUTPUT_FLAGS.get(cmd)
        if flags:
            for k, a in enumerate(args[1:-1], start=1):
                if a in flags:
                    out.append(("write", args[k + 1]))
        rest = [a for a in args[1:] if not a.startswith("-")]
        if cmd == "tee":
            out += [("write", a) for a in rest]
        elif cmd in _PS_DELETE:
            out += [("delete", a) for a in rest]
        elif cmd == "touch" or cmd in _PS_WRITE_FIRST:
            out += [("write", a) for a in (rest if cmd == "touch" else rest[:1])]
        elif cmd in _PS_MOVE and len(rest) >= 2:
            out += [("delete", a) for a in rest[:-1]] + [("write", rest[-1])]
        elif cmd in _PS_COPY and len(rest) >= 2:
            out += [("read", a) for a in rest[:-1]] + [("write", rest[-1])]
        elif cmd == "sed" and any(a.startswith("-i") for a in args[1:]) and rest:
            out.append(("write", rest[-1]))
        elif (
            cmd in ("cat", "head", "tail", "less", "wc", "grep", "rg", "type")
            or cmd in _PS_READ
        ) and rest:
            out += [("read", a) for a in rest[-1:] if "/" in a or "." in a]
    # A bare variable (`$FILE`) names nothing we can match; `$HOME/.env` does.
    return [(k, p) for k, p in out if p and not (p.startswith("$") and "/" not in p)]


def effects(step) -> list[Effect]:
    """Files this step read, wrote or deleted (see module doc for confidence)."""
    tool = canonical_name(step.tool)
    args = step.args if isinstance(step.args, dict) else {}
    found: list[tuple[str, str, str]] = []
    if tool in PATCH_TOOLS or (
        "*** Begin Patch" in json.dumps(args, default=str)[:400000]
        and tool in SHELL_TOOLS | PATCH_TOOLS
    ):
        blob = " ".join(v for v in _walk_strings(args))
        for kind, path in _PATCH_RE.findall(blob):
            found.append(("delete" if kind == "Delete" else "write", path, "declared"))
        for path in _PATCH_MOVE_RE.findall(blob):
            found.append(("write", path, "declared"))
    elif tool in WRITE_TOOLS or tool.endswith(("__write_file", "__edit_file")):
        path = _first_str(args, _PATH_KEYS)
        if path:
            cmd = args.get("command")
            kind = "read" if cmd == "view" else "write"
            found.append((kind, path, "declared"))
    elif tool in READ_TOOLS or tool.endswith("__read_file"):
        path = _first_str(args, _PATH_KEYS)
        if path:
            found.append(("read", path, "declared"))
    elif tool in SHELL_TOOLS:
        cmd = args.get("command", args.get("cmd", args.get("script")))
        if isinstance(cmd, list):
            cmd = " ".join(str(c) for c in cmd)
        if isinstance(cmd, str):
            found += [(k, p, "inferred") for k, p in _shell_effects(cmd)]
    seen = set()
    result = []
    for kind, path, how in found:
        norm = _norm_path(path)
        if not norm or (kind, norm) in seen:
            continue
        seen.add((kind, norm))
        result.append(Effect(step.n, kind, norm, how, step.tool, step.ok))
    return result


def _walk_strings(obj, depth: int = 0):
    if depth > 20:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _walk_strings(v, depth + 1)
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_strings(v, depth + 1)


def args_text(args, limit: int = 200_000) -> str:
    """Every string in a call's arguments, newline-joined, as plain text.

    Policy regexes (`--forbid-arg`, the audit's destructive patterns) should
    see the command as written (`C:\\Users`, real newlines), not as a JSON
    encoding of it with doubled backslashes and `\\n` escapes.
    """
    out: list[str] = []
    size = 0
    for text in _walk_strings(args):
        out.append(text)
        size += len(text)
        if size > limit:
            break
    return "\n".join(out)[:limit]


def file_ledger(session) -> dict[str, list[Effect]]:
    """Path -> ordered effects across the whole session."""
    ledger: dict[str, list[Effect]] = {}
    for step in session.steps:
        for eff in effects(step):
            ledger.setdefault(eff.path, []).append(eff)
    return ledger


def _path_matches(candidate: str, query: str) -> bool:
    q = _norm_path(query)
    if q.startswith("~/"):
        q = "*/" + q[2:]  # a policy about ~/.ssh must catch /home/x/.ssh too
    if _WIN_PATH_RE.match(candidate) or _WIN_PATH_RE.match(q):
        # Windows file systems are case-insensitive by default.
        candidate, q = candidate.casefold(), q.casefold()
    if candidate == q:
        return True
    if not q.startswith("/") and candidate.endswith("/" + q):
        return True
    return fnmatch.fnmatchcase(candidate, q) or fnmatch.fnmatchcase(candidate, "*/" + q)


def blame(session, path: str) -> list[Effect]:
    """Every step that wrote/deleted/read ``path`` (suffix and glob match)."""
    hits: list[Effect] = []
    for p, effs in file_ledger(session).items():
        if _path_matches(p, path):
            hits += effs
    return sorted(hits, key=lambda e: (e.step, e.kind))


# ---------------------------------------------------------------------------
# Why did the agent do that?
# ---------------------------------------------------------------------------

_TOKEN_RE = re.compile(r"[^\s\"'`,;()\[\]{}<>=|&]+")


def _candidate_values(args) -> list[str]:
    """Concrete strings in the args worth tracing (paths, URLs, ids, names)."""
    seen: dict[str, None] = {}
    for text in _walk_strings(args):
        if len(text) > 4000:
            text = text[:4000]
        pieces = [text] if len(text) <= 200 and not text.split(None, 1)[1:] else _TOKEN_RE.findall(text)
        for piece in pieces:
            piece = piece.strip(".:,")
            if len(piece) < 5 or len(piece) > 200:
                continue
            interesting = (
                "/" in piece or "." in piece[1:-1] or "_" in piece
                or any(c.isdigit() for c in piece) or piece.startswith(("http", "~"))
            )
            if interesting and not piece.startswith("-"):
                seen[piece] = None
        if len(seen) >= 40:
            break
    return list(seen)


@dataclass
class Provenance:
    value: str
    origin: str  # "prompt" | "step N output" | "step N args" | "model text" | "nowhere"
    step: int | None = None


@dataclass
class Explanation:
    step: int
    tool: str
    ok: bool | None
    prompt: str | None
    model_text: str | None
    turn_steps: list[tuple[int, str, bool | None]] = field(default_factory=list)
    provenance: list[Provenance] = field(default_factory=list)
    effects: list[Effect] = field(default_factory=list)
    next_steps: list[tuple[int, str, bool | None]] = field(default_factory=list)

    @property
    def unsourced(self) -> list[Provenance]:
        return [p for p in self.provenance if p.origin == "nowhere"]


def explain(session, n: int, max_values: int = 12) -> Explanation:
    """Build the causal story for step ``n``.

    Method: take the concrete values in the step's arguments and search, in
    order, the user prompts, model text and earlier tool arguments/outputs
    that the agent had seen *before* this call. Substring match on the
    stored text, so outputs cut at 20,000 characters can hide an origin
    (reported as "nowhere" - verify against the full log before blaming
    the model).
    """
    step = session.get_step(n)
    call_idx = None
    for i, ev in enumerate(session.events):
        if ev is step.call:
            call_idx = i
            break
    # Only what existed before the call is a legitimate source.
    before = session.events[:call_idx] if call_idx is not None else session.events
    prompts = [e for e in before if e.get("type") == "prompt"]
    responses = [e for e in before if e.get("type") == "response"]
    last_prompt = prompts[-1] if prompts else None
    turn_start = 0
    for i in range(len(before) - 1, -1, -1):
        if before[i] is last_prompt:
            turn_start = i
            break
    turn_call_ids = {
        e.get("id") for e in before[turn_start:] if e.get("type") == "tool_call"
    }
    turn_steps = [
        (s.n, s.tool, s.ok)
        for s in session.steps[: n - 1]
        if s.call is not None and s.call.get("id") in turn_call_ids
    ]
    exp = Explanation(
        step=n,
        tool=step.tool,
        ok=step.ok,
        prompt=(last_prompt or {}).get("text"),
        model_text=step.response_ctx.get("text") if step.response_ctx else None,
        turn_steps=turn_steps,
        effects=effects(step),
        next_steps=[(s.n, s.tool, s.ok) for s in session.steps[n : n + 3]],
    )

    corpus: list[tuple[str, int | None, str]] = []
    for p in prompts:
        corpus.append(("prompt", None, str(p.get("text", "")).lower()))
    for r in responses:
        corpus.append(("model text", None, str(r.get("text", "")).lower()))
    for s in session.steps[: n - 1]:
        corpus.append(
            ("args", s.n, json.dumps(s.args, default=str, ensure_ascii=False).lower())
        )
        corpus.append(("output", s.n, (s.output or "").lower()))
    for value in _candidate_values(step.args)[:max_values]:
        needle = value.lower()
        origin = Provenance(value, "nowhere")
        for kind, sn, text in corpus:
            if needle in text:
                if kind == "prompt":
                    origin = Provenance(value, "prompt")
                elif kind == "model text":
                    origin = Provenance(value, "model text")
                else:
                    origin = Provenance(value, f"step {sn} {kind}", sn)
                break
        exp.provenance.append(origin)
    return exp


# ---------------------------------------------------------------------------
# Breakpoints
# ---------------------------------------------------------------------------


@dataclass
class Breakpoint:
    """A stop condition for ``continue`` / ``reverse-continue``.

    Specs: ``fail`` (a failed step), ``slow:MS`` (took longer than MS),
    ``file:PATH`` (touches PATH; globs allowed), ``~REGEX`` (matches the
    tool name, args or output, case-insensitive), or a tool-name glob
    such as ``Bash`` or ``mcp__*``.
    """

    spec: str
    kind: str
    arg: str
    number: int = 0
    temporary: bool = False
    hits: int = 0

    @classmethod
    def parse(cls, spec: str, temporary: bool = False) -> Breakpoint:
        spec = spec.strip()
        if not spec:
            raise ValueError("empty breakpoint")
        low = spec.lower()
        if low in ("fail", "failed", "error"):
            return cls(spec, "fail", "", temporary=temporary)
        if low.startswith("slow:"):
            try:
                ms = float(spec[5:])
            except ValueError:
                raise ValueError("slow:MS needs a number of milliseconds") from None
            return cls(spec, "slow", str(ms), temporary=temporary)
        if low.startswith("file:"):
            return cls(spec, "file", spec[5:], temporary=temporary)
        if spec.startswith("~"):
            pattern = spec[1:]
            if len(pattern) > 500:
                raise ValueError("regex too long")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"bad regex: {exc}") from None
            return cls(spec, "regex", pattern, temporary=temporary)
        return cls(spec, "tool", spec, temporary=temporary)

    def matches(self, step) -> bool:
        if self.kind == "fail":
            return step.ok is False
        if self.kind == "slow":
            d = step.duration_ms
            return d is not None and d > float(self.arg)
        if self.kind == "file":
            return any(_path_matches(e.path, self.arg) for e in effects(step))
        if self.kind == "regex":
            hay = " ".join(
                (step.tool, json.dumps(step.args, default=str), step.output or "",
                 step.error or "")
            )
            return re.search(self.arg, hay, re.I) is not None
        return fnmatch.fnmatchcase(canonical_name(step.tool), canonical_name(self.arg))


def run_to_breakpoint(session, cursor: int, breakpoints, reverse: bool = False):
    """Return (step_number, breakpoint) of the next hit, or (None, None)."""
    rng = range(cursor - 1, 0, -1) if reverse else range(cursor + 1, len(session.steps) + 1)
    for n in rng:
        step = session.steps[n - 1]
        for bp in breakpoints:
            if bp.matches(step):
                return n, bp
    return None, None
