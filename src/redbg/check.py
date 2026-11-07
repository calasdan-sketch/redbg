"""CI gate: fail a build when an agent run regresses or breaks a rule.

``run_check`` evaluates one *candidate* session against

- an optional *baseline* session: any alignment change whose kind is in
  ``fail_on`` is a violation (by default every kind except ``same``), and
- explicit policy rules: completion, step budget, failure budget,
  forbidden/required tools (shell-style globs), and loop detection.

It is pure data in, data out — the CLI (``redbg check``) maps the result
to exit codes: 0 pass, 1 violations, 2 could not run.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from xml.etree import ElementTree as ET

from ._text import canonical_name, clean, name_variants
from .analysis import _path_matches, args_text, effects
from .diff import (
    ALL_KINDS,
    CHANGE_KINDS,
    OUTPUT_CHANGED,
    align_steps,
    find_cycles,
    find_divergence,
    find_repeats,
    output_changed,
)
from .replay import Session

FAIL_ON_CHOICES = (*CHANGE_KINDS, OUTPUT_CHANGED)


@dataclass
class CheckRules:
    require_complete: bool = True
    """Session must end with status ``ok`` and every step must have a result."""
    max_steps: int | None = None
    max_failures: int | None = None
    forbid_tools: list[str] = field(default_factory=list)
    """Glob patterns (``delete_*``); any matching call is a violation.
    Matching is case-insensitive and Unicode-normalized (NFKC, format
    characters dropped) on both sides — see ``canonical_name``."""
    require_tools: list[str] = field(default_factory=list)
    """Glob patterns; each must match at least one call (same matching)."""
    max_repeats: int | None = None
    """Max allowed run of identical consecutive calls (loop detector)."""
    max_tokens: int | None = None
    """Budget for input + output + cache-read + cache-creation tokens over
    the whole session (counts, not cost). A trace with no usage data fails
    this rule: an unmeasured run must not pass a budget."""
    max_cycles: int | None = None
    """Max allowed repeats of an alternating call pattern (``a, b, a, b``...)
    of 2-8 calls; a pattern repeated more than this many times fails."""
    forbid_paths: list[str] = field(default_factory=list)
    """Path globs; a step that reads, writes or deletes a matching file fails.
    Paths are those ``redbg files`` reports (shell commands are inferred)."""
    forbid_writes: list[str] = field(default_factory=list)
    """Like ``forbid_paths`` but only writes and deletes count."""
    forbid_args: list[str] = field(default_factory=list)
    """Regexes searched (case-insensitive) in each call's tool name and
    arguments, e.g. ``rm\\s+-rf`` or ``git push.*--force``. Your regex runs
    over every call: keep it simple."""
    fail_on: tuple[str, ...] = CHANGE_KINDS
    """Baseline diff kinds that count as a regression."""
    ignore_keys: tuple[str, ...] = ()
    """Arg keys ignored when comparing against the baseline / finding loops."""
    allow_empty: bool = False
    """By default a trace with zero tool steps, or a check with no rules to
    evaluate, fails: a crashed or misconfigured recorder must not pass CI."""

    def __post_init__(self) -> None:
        bad = [k for k in self.fail_on if k not in FAIL_ON_CHOICES]
        if bad:
            raise ValueError(
                f"unknown fail_on kind(s) {bad}; choose from {list(FAIL_ON_CHOICES)}"
            )
        for pattern in self.forbid_args:
            if len(pattern) > 500:
                raise ValueError("forbid_args pattern too long (max 500 chars)")
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ValueError(f"bad forbid_args regex {pattern!r}: {exc}") from None
        for name in ("max_steps", "max_failures", "max_repeats", "max_cycles", "max_tokens"):
            value = getattr(self, name)
            if value is not None and value < 0:
                raise ValueError(f"{name} must be >= 0, got {value}")


@dataclass
class Violation:
    rule: str
    message: str
    step: int | None = None

    def to_dict(self) -> dict:
        return {"rule": self.rule, "message": self.message, "step": self.step}


@dataclass
class CheckResult:
    candidate: str
    baseline: str | None
    violations: list[Violation]
    checked: list[str]

    @property
    def passed(self) -> bool:
        return not self.violations

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "candidate": self.candidate,
            "baseline": self.baseline,
            "checked": self.checked,
            "violations": [v.to_dict() for v in self.violations],
        }


def run_check(
    candidate: Session, rules: CheckRules, baseline: Session | None = None
) -> CheckResult:
    violations: list[Violation] = []
    checked: list[str] = []
    steps = candidate.steps

    if not rules.allow_empty:
        checked.append("non_empty")
        if not steps:
            violations.append(
                Violation(
                    "non_empty",
                    "trace has no tool steps (empty, unparseable or crashed "
                    "before the first call?); use --allow-empty (allow_empty=True) to accept",
                )
            )

    if rules.require_complete:
        checked.append("complete")
        if candidate.status != "ok":
            what = (
                "no session_end event (crashed or still running?)"
                if candidate.status is None
                else f"session ended with status {candidate.status!r}"
            )
            violations.append(Violation("complete", what))
        for step in steps:
            if step.result is None:
                violations.append(
                    Violation(
                        "complete", f"step {step.n} ({step.tool}) has no result", step.n
                    )
                )
            elif step.call is None:
                violations.append(
                    Violation(
                        "complete",
                        f"step {step.n} ({step.tool}) is a result with no call",
                        step.n,
                    )
                )

    if rules.max_steps is not None:
        checked.append("max_steps")
        if len(steps) > rules.max_steps:
            violations.append(
                Violation(
                    "max_steps", f"{len(steps)} steps > budget of {rules.max_steps}"
                )
            )

    if rules.max_failures is not None:
        checked.append("max_failures")
        failed = [s.n for s in steps if s.ok is False]
        if len(failed) > rules.max_failures:
            violations.append(
                Violation(
                    "max_failures",
                    f"{len(failed)} failed step(s) > budget of {rules.max_failures} "
                    f"(steps {', '.join(map(str, failed[:20]))}"
                    f"{', …' if len(failed) > 20 else ''})",
                    failed[0],
                )
            )

    if rules.forbid_tools:
        checked.append("forbid_tools")
        forbid = [(p, canonical_name(p)) for p in rules.forbid_tools]
        for step in steps:
            variants = name_variants(step.tool)
            for pattern, canon in forbid:
                if any(fnmatchcase(v, canon) for v in variants):
                    violations.append(
                        Violation(
                            "forbid_tools",
                            f"step {step.n} called forbidden tool {step.tool!r} "
                            f"(matches {pattern!r})",
                            step.n,
                        )
                    )
                    break

    if rules.require_tools:
        checked.append("require_tools")
        for pattern in rules.require_tools:
            canon = canonical_name(pattern)
            if not any(
                fnmatchcase(v, canon) for s in steps for v in name_variants(s.tool)
            ):
                violations.append(
                    Violation(
                        "require_tools", f"no call matched required tool {pattern!r}"
                    )
                )

    if rules.forbid_paths or rules.forbid_writes:
        checked.append("forbid_paths")
        for step in steps:
            for eff in effects(step):
                hit = next(
                    (g for g in rules.forbid_paths if _path_matches(eff.path, g)), None
                ) or (
                    next(
                        (g for g in rules.forbid_writes if _path_matches(eff.path, g)),
                        None,
                    )
                    if eff.kind in ("write", "delete")
                    else None
                )
                if hit:
                    how = "inferred from a shell command" if eff.how == "inferred" else "declared"
                    failed = " (the step failed, but it tried)" if step.ok is False else ""
                    violations.append(
                        Violation(
                            "forbid_paths",
                            f"step {step.n} ({step.tool}) {eff.kind}s {eff.path!r} "
                            f"(matches {hit!r}; {how}){failed}",
                            step.n,
                        )
                    )

    if rules.forbid_args:
        checked.append("forbid_args")
        compiled = [(p, re.compile(p, re.I)) for p in rules.forbid_args]
        for step in steps:
            hay = canonical_name(step.tool + "\n" + args_text(step.args))
            for pattern, rx in compiled:
                if rx.search(hay):
                    violations.append(
                        Violation(
                            "forbid_args",
                            f"step {step.n} ({step.tool}) matches forbidden "
                            f"pattern {pattern!r}",
                            step.n,
                        )
                    )
                    break

    if rules.max_repeats is not None:
        checked.append("max_repeats")
        for run in find_repeats(candidate, min_count=2, ignore_keys=rules.ignore_keys):
            if run.count > rules.max_repeats:
                violations.append(
                    Violation(
                        "max_repeats",
                        f"{run.tool!r} called {run.count}× in a row with identical "
                        f"args (steps {run.first}-{run.last}); limit "
                        f"{rules.max_repeats} — possible loop",
                        run.first,
                    )
                )

    if rules.max_tokens is not None:
        checked.append("max_tokens")
        if not candidate.usage:
            violations.append(
                Violation(
                    "max_tokens",
                    "no token usage in this trace, so the budget cannot be "
                    "checked (Claude Code transcripts and Recorder.usage() "
                    "provide it)",
                )
            )
        elif candidate.total_tokens > rules.max_tokens:
            u = candidate.usage
            violations.append(
                Violation(
                    "max_tokens",
                    f"{candidate.total_tokens:,} tokens > budget of "
                    f"{rules.max_tokens:,} (input {u['input']:,}, output "
                    f"{u['output']:,}, cache read {u['cache_read']:,}, cache "
                    f"creation {u['cache_creation']:,})",
                )
            )

    if rules.max_cycles is not None:
        checked.append("max_cycles")
        for cyc in find_cycles(candidate, min_reps=2, ignore_keys=rules.ignore_keys):
            if cyc.reps > rules.max_cycles:
                shape = " -> ".join(cyc.tools)
                violations.append(
                    Violation(
                        "max_cycles",
                        f"pattern [{shape}] repeated {cyc.reps}× "
                        f"(steps {cyc.first}-{cyc.last}); limit "
                        f"{rules.max_cycles} — possible loop",
                        cyc.first,
                    )
                )

    if baseline is not None:
        checked.append("baseline")
        rows = align_steps(baseline, candidate, rules.ignore_keys)
        fail_on = set(rules.fail_on)
        div = find_divergence(baseline, candidate, rows, rules.ignore_keys)
        regressions = 0
        for row in rows:
            kinds = []
            if row.kind in fail_on:
                kinds.append(row.kind)
            if OUTPUT_CHANGED in fail_on and output_changed(row):
                kinds.append(OUTPUT_CHANGED)
            for kind in kinds:
                regressions += 1
                where = f"baseline:{row.a_n or '—'} / candidate:{row.b_n or '—'}"
                tool = (row.b_step or row.a_step).tool
                violations.append(Violation(kind, f"{where} {tool!r}: {kind}", row.b_n))
        if regressions and div is not None and div.kind in fail_on:
            # Put the human headline first: it is the single most useful line.
            violations.insert(
                len(violations) - regressions,
                Violation("divergence", div.headline, div.b_n),
            )

    rule_checks = [c for c in checked if c != "non_empty"]
    if not rule_checks and not rules.allow_empty:
        violations.append(
            Violation(
                "no_rules",
                "nothing was checked (all rules disabled); add a rule or a "
                "baseline, or pass allow_empty to accept",
            )
        )

    return CheckResult(
        candidate=candidate.path,
        baseline=baseline.path if baseline is not None else None,
        violations=violations,
        checked=checked,
    )


def to_github(result: CheckResult, limit: int = 0) -> str:
    """GitHub Actions workflow commands, one ``::error`` per violation.

    Violation text comes from untrusted traces, so it is made printable and
    escaped the way the runner requires (``%``, CR and LF in the message;
    also ``:`` and ``,`` in properties) - a tool name containing a newline
    can't forge a second workflow command.
    """

    def esc(text: str) -> str:
        return (
            clean(text).replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
        )

    title = "redbg check"
    lines = []
    shown = result.violations[:limit] if limit > 0 else result.violations
    for v in shown:
        rule = esc(v.rule).replace(":", "%3A").replace(",", "%2C")
        lines.append(f"::error title={title} [{rule}]::{esc(v.message)}")
    if len(shown) < len(result.violations):
        lines.append(
            f"::error title={title}::{len(result.violations) - len(shown)} more "
            "violation(s) not shown (--limit 0 shows all)"
        )
    if not lines:
        lines.append("::notice title=redbg check::passed")
    return "\n".join(lines)


_XML_BAD = re.compile("[^\t\n\r\u0020-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]")


def _xml_text(text) -> str:
    """Printable text that is also legal XML 1.0 (no U+FFFE/U+FFFF etc.)."""
    return _XML_BAD.sub(lambda m: f"\\u{ord(m.group()):04x}", clean(text))


def to_junit(result: CheckResult) -> str:
    """JUnit XML: one test case per rule checked, failures carry the messages."""
    by_rule: dict[str, list[Violation]] = {}
    for v in result.violations:
        by_rule.setdefault(v.rule, []).append(v)
    rules = list(dict.fromkeys([*result.checked, *by_rule]))
    suite = ET.Element(
        "testsuite",
        name="redbg check",
        tests=str(len(rules)),
        failures=str(len(by_rule)),
    )
    for rule in rules:
        case = ET.SubElement(
            suite, "testcase", classname="redbg", name=_xml_text(rule)
        )
        if rule in by_rule:
            msgs = [_xml_text(v.message) for v in by_rule[rule]]
            ET.SubElement(
                case, "failure", message=msgs[0], type=_xml_text(rule)
            ).text = "\n".join(msgs)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(
        suite, encoding="unicode"
    )


__all__ = [
    "to_github",
    "to_junit",
    "ALL_KINDS",
    "FAIL_ON_CHOICES",
    "CheckRules",
    "CheckResult",
    "Violation",
    "run_check",
]
