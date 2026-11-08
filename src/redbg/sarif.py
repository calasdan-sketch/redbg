"""SARIF 2.1.0 reports for ``check`` and ``audit`` (GitHub code scanning etc.).

The report is built from data only (no network, no extra dependency). A
trace has no source lines, so each result points at the trace file itself and
names the step in ``logicalLocations`` and ``properties``.
"""

from __future__ import annotations

import json
import os
from urllib.parse import quote

from ._meta import AUTHOR, REPOSITORY
from ._text import clean

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
_LEVEL = {"high": "error", "medium": "warning", "low": "note"}


def _uri(path: str) -> str:
    """Trace path as a relative URI with forward slashes (untrusted text is escaped)."""
    try:
        rel = os.path.relpath(path)
    except ValueError:  # another drive on Windows
        rel = path
    if rel.startswith(".."):
        rel = path
    return quote(rel.replace("\\", "/"), safe="/:")


def _build(version: str, trace: str, items: list[dict], rules: dict[str, str]) -> dict:
    results = []
    for it in items:
        result: dict = {
            "ruleId": it["rule"],
            "level": it["level"],
            "message": {"text": clean(it["message"])},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": _uri(trace), "index": 0}
                    }
                }
            ],
        }
        if it.get("step"):
            result["locations"][0]["logicalLocations"] = [
                {"name": f"step {it['step']}", "kind": "member"}
            ]
            result["properties"] = {"step": it["step"]}
        results.append(result)
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "redbg",
                        "version": version,
                        "organization": AUTHOR,
                        "informationUri": REPOSITORY,
                        "rules": [
                            {
                                "id": rid,
                                "name": rid,
                                "shortDescription": {"text": clean(text)},
                            }
                            for rid, text in sorted(rules.items())
                        ],
                    }
                },
                "artifacts": [{"location": {"uri": _uri(trace)}}],
                "results": results,
            }
        ],
    }


def check_to_sarif(result, version: str) -> str:
    """SARIF text for a ``CheckResult`` (every violation is level ``error``)."""
    items = [
        {"rule": v.rule, "level": "error", "message": v.message, "step": v.step}
        for v in result.violations
    ]
    rules = {v.rule: f"redbg check rule: {v.rule}" for v in result.violations}
    return json.dumps(_build(version, result.candidate, items, rules), indent=2)


def audit_to_sarif(findings, trace: str, version: str) -> str:
    """SARIF text for audit findings (high=error, medium=warning, low=note)."""
    items = [
        {
            "rule": f.kind,
            "level": _LEVEL.get(f.severity, "note"),
            "message": f.message,
            "step": f.step,
        }
        for f in findings
    ]
    rules = {f.kind: f"redbg audit finding: {f.kind}" for f in findings}
    return json.dumps(_build(version, trace, items, rules), indent=2)
