"""``redbg audit``: rank the suspicious steps of a session.

``why`` answers a question you already have; ``audit`` finds the question.
It scans the whole session once and lists, most serious first:

* ``invented_path``  - a path or URL in a call that appears nowhere in what
  the agent had seen so far (prompts, its own text, earlier arguments and
  outputs). High when the tool then failed with a "not found" error.
* ``destructive``    - commands like ``rm -rf``, ``git reset --hard``,
  ``git push --force``, ``DROP TABLE``, ``curl ... | sh``.
* ``retried_failure``, ``failure_streak``, ``loop``, ``cycle`` - the agent
  repeating itself or failing over and over.
* ``incomplete``     - the session never finished.
* ``secrets``        - values shaped like credentials are in the trace.

Everything is a heuristic over stored text: a finding is a lead for a human,
not a verdict. Paths the agent *creates* (a Write to a new file) are not
treated as invented, and outputs cut at the size limit can hide an origin.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass

from ._text import canonical_name
from .analysis import READ_TOOLS, SHELL_TOOLS, _candidate_values, args_text, effects
from .diff import find_cycles, find_repeats
from .redact import redact_event

HIGH, MEDIUM, LOW = "high", "medium", "low"
_RANK = {HIGH: 0, MEDIUM: 1, LOW: 2}

_PATHISH = re.compile(r"^(?:[A-Za-z]:[\\/]|[/~]|\.{1,2}[\\/]|https?://|[\w.-]+/[\w./-]+)")
# A bare file name (`wrong.py`): only suspicious when the tool said not-found.
_FILEISH = re.compile(r"^[\w][\w.-]*\.[A-Za-z0-9]{1,8}$")
_BENIGN_PREFIXES = (
    "/dev/", "/proc/", "/sys/", "/tmp/", "/var/tmp/", "/bin/", "/sbin/",
    "/usr/bin/", "/usr/local/bin/", "/usr/sbin/", "/lib/", "/usr/lib/",
)
_NOT_FOUND = re.compile(
    r"no such file|not found|does not exist|enoent|cannot find|404|"
    r"is not a directory|couldn't find|could not find",
    re.I,
)
# Case-folded (the haystack is canonicalized before matching).
_DESTRUCTIVE = [
    (r"\brm\s+(?:-[a-z]*r[a-z]*|--recursive)\b", "recursive delete (rm -r)"),
    (r"\bgit\s+reset\s+(?:\S+\s+)*--hard\b", "git reset --hard"),
    (r"\bgit\s+clean\s+(?:\S+\s+)*-[a-z]*f", "git clean -f"),
    (r"\bgit\s+push\b[^|;&\n]*(?:--force\b|--force-with-lease|\s-f\b)", "force push"),
    (r"\bgit\s+push\b[^|;&\n]*\s\+[\w/]", "force push (+refspec)"),
    (r"\bfind\b[^|;&\n]*\s-delete\b", "find -delete"),
    (r"\bgit\s+checkout\s+(?:--\s+)?\.(?:\s|$)", "git checkout . (discards edits)"),
    (r"\bdrop\s+(?:table|database|schema)\b", "SQL DROP"),
    (r"\btruncate\s+table\b", "SQL TRUNCATE"),
    (r"\bdelete\s+from\s+\w+\s*(?:;|\"|'|$)", "SQL DELETE without WHERE"),
    (r"\bchmod\s+(?:-r\s+)?(?:a\+rwx|777)\b", "chmod 777"),
    (r"\bmkfs(?:\.\w+)?\b|\bdd\b[^|;&\n]*\bof=/dev/", "disk overwrite"),
    (r"\b(?:curl|wget)\b[^|;&\n]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b", "pipe download into a shell"),
    (r"\bremove-item\b[^|;&\n]*-recurse", "Remove-Item -Recurse"),
    (r"\b(?:rd|rmdir|del)\s+/s\b", "cmd recursive delete"),
    (r"\bformat\s+[a-z]:", "format drive"),
]
_DESTRUCTIVE_RES = [(re.compile(p), label) for p, label in _DESTRUCTIVE]


@dataclass
class Finding:
    severity: str
    kind: str
    step: int | None
    message: str

    def to_dict(self) -> dict:
        return {
            "severity": self.severity,
            "kind": self.kind,
            "step": self.step,
            "message": self.message,
        }


def _is_benign(value: str) -> bool:
    low = value.lower()
    return low.startswith(_BENIGN_PREFIXES) or low in ("/", ".", "..")


def _path_tokens(text: str, into: set) -> None:
    """Remember every path-like token, plus its parent dirs and tail paths."""
    for tok in re.split(r"[\s\"'`,;()\[\]{}<>=|&*?]+", text):
        tok = tok.strip(".:")
        if len(tok) < 3 or ("/" not in tok and "\\" not in tok) or len(tok) > 500:
            continue
        low = tok.lower().replace("\\", "/")
        if low.startswith("file://"):
            low = low[7:]
        parts = low.split("/")
        for i in range(len(parts)):
            into.add("/".join(parts[i:]))  # tail paths: a/b/c, b/c, c
        for i in range(2, len(parts)):
            into.add("/".join(parts[:i]))  # parent dirs


def audit(
    session,
    *,
    check_secrets: bool = True,
    substring_budget: int = 30_000_000,
) -> list[Finding]:
    """Return findings, most serious first. See the module docstring."""
    findings: list[Finding] = []
    steps = session.steps
    if session.status != "ok":
        what = (
            "no end marker (crashed, still running, or a log format without one)"
            if session.status is None
            else f"ended with status {session.status!r}"
        )
        findings.append(Finding(MEDIUM, "incomplete", None, f"session {what}"))

    # Everything the agent could have seen before step n, in event order.
    seen_tokens: set[str] = set()
    corpus: list[str] = []
    corpus_chars = 0
    step_by_call = {id(s.call): s for s in steps if s.call is not None}
    fail_streak = 0
    streak_start = 0

    def feed(text: str) -> None:
        nonlocal corpus_chars
        if not text:
            return
        low = text.lower()
        _path_tokens(low, seen_tokens)
        if corpus_chars < substring_budget:
            corpus.append(low)
            corpus_chars += len(low)

    for ev in session.events:
        etype = ev.get("type")
        if etype in ("prompt", "response"):
            feed(str(ev.get("text", "")))
        elif etype == "tool_result":
            feed(str(ev.get("output", "")))
            feed(str(ev.get("error", "")))
        elif etype == "tool_call":
            step = step_by_call.get(id(ev))
            if step is None:
                continue
            _audit_call(step, seen_tokens, corpus, findings)
            feed(json.dumps(step.args, default=str, ensure_ascii=False))
            if step.ok is False:
                if fail_streak == 0:
                    streak_start = step.n
                fail_streak += 1
            else:
                _flush_streak(findings, fail_streak, streak_start, step.n - 1)
                fail_streak = 0
    _flush_streak(findings, fail_streak, streak_start, steps[-1].n if steps else 0)

    for run in find_repeats(session, min_count=3):
        failed = all(
            s.ok is False for s in steps[run.first - 1 : run.last]
        )
        if failed:
            findings.append(
                Finding(
                    HIGH, "retried_failure", run.first,
                    f"{run.tool!r} failed {run.count}x in a row with identical "
                    f"arguments (steps {run.first}-{run.last})",
                )
            )
        elif run.count >= 4:
            findings.append(
                Finding(
                    HIGH if run.count >= 8 else MEDIUM, "loop", run.first,
                    f"{run.tool!r} called {run.count}x in a row with identical "
                    f"arguments (steps {run.first}-{run.last})",
                )
            )
    for cyc in find_cycles(session, min_reps=3):
        findings.append(
            Finding(
                HIGH if cyc.reps >= 6 else MEDIUM, "cycle", cyc.first,
                f"pattern [{' -> '.join(cyc.tools)}] repeated {cyc.reps}x "
                f"(steps {cyc.first}-{cyc.last})",
            )
        )

    if check_secrets:
        hits = 0
        for ev in session.events:
            _, count = redact_event(ev)
            if count:
                hits += count
        if hits:
            findings.append(
                Finding(
                    MEDIUM, "secrets", None,
                    f"{hits} value(s) shaped like credentials in the trace; "
                    "run `redbg redact` before sharing",
                )
            )
    findings.sort(key=lambda f: (_RANK[f.severity], f.step or 0, f.kind))
    return findings


def _flush_streak(findings, count: int, first: int, last: int) -> None:
    if count >= 5:
        findings.append(
            Finding(
                HIGH, "failure_streak", first,
                f"{count} failed steps in a row (steps {first}-{last})",
            )
        )


def _audit_call(step, seen_tokens, corpus, findings) -> None:
    args = step.args if isinstance(step.args, dict) else {}
    # destructive commands (tool name + args, canonicalized)
    hay = canonical_name(step.tool + "\n" + args_text(step.args))
    for rx, label in _DESTRUCTIVE_RES:
        if rx.search(hay):
            findings.append(
                Finding(HIGH, "destructive", step.n, f"{step.tool}: {label}")
            )
            break
    # Invented paths: only for calls that must find something that exists.
    # Creating a new file with Write is not "inventing" its name.
    effs = effects(step)
    tool = canonical_name(step.tool)
    is_shell = tool in SHELL_TOOLS
    err = (step.error or "") + " " + (step.output or "")[:2000]
    not_found = step.ok is False and bool(_NOT_FOUND.search(err))
    edits_existing = any(e.kind == "write" for e in effs) and not any(
        k in args for k in ("content", "file_text", "text")
    )
    if not_found:
        values = [
            v
            for v in _candidate_values(args)[:12]
            if _PATHISH.match(v) or _FILEISH.match(v)
        ]
    elif is_shell:  # only what the command reads or deletes, not mkdir/new files
        values = [e.path for e in effs if e.kind in ("read", "delete")]
    elif tool in READ_TOOLS or tool.endswith("__read_file") or edits_existing or any(
        e.kind in ("read", "delete") for e in effs
    ):
        values = [v for v in _candidate_values(args)[:12] if _PATHISH.match(v)]
    else:
        return
    for value in values:
        if _is_benign(value):
            continue
        low = value.lower().replace("\\", "/")
        norm = low[2:] if low.startswith("./") else low.rstrip("/") or low
        if low in seen_tokens or norm in seen_tokens:
            continue
        if any(low in text or value.lower() in text for text in corpus):
            continue
        findings.append(
            Finding(
                HIGH if not_found else MEDIUM,
                "invented_path",
                step.n,
                f"{step.tool}: {value!r} appears nowhere the agent had seen"
                + (" and the call failed with a not-found error" if not_found else ""),
            )
        )
        break  # one finding per step is enough to point a human at it


__all__ = ["Finding", "audit", "HIGH", "MEDIUM", "LOW"]
