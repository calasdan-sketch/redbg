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

from dataclasses import dataclass, field
from fnmatch import fnmatchcase

from ._text import canonical_name
from .diff import (
    ALL_KINDS,
    CHANGE_KINDS,
    OUTPUT_CHANGED,
    align_steps,
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
        for name in ("max_steps", "max_failures", "max_repeats"):
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
    names = [canonical_name(s.tool) for s in steps]

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
        for step, tool_name in zip(steps, names):
            for pattern, canon in forbid:
                if fnmatchcase(tool_name, canon):
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
            if not any(fnmatchcase(name, canon) for name in names):
                violations.append(
                    Violation(
                        "require_tools", f"no call matched required tool {pattern!r}"
                    )
                )

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


__all__ = [
    "ALL_KINDS",
    "FAIL_ON_CHOICES",
    "CheckRules",
    "CheckResult",
    "Violation",
    "run_check",
]
