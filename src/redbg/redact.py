"""Secrets redaction for redbg traces.

Two jobs:
1. ``redact_event`` — applied at record time (and by ``redbg redact``) to strip
   secrets from a trace before it is written or shared.
2. ``scan_file`` — audits an existing trace for values that *look* secret but
   were not redacted, so you can check before sharing.

Redaction is structural: values of keys whose names look sensitive are
replaced wholesale, and string values matching known token shapes are
replaced wherever they appear.
"""

from __future__ import annotations

import gzip
import json
import re

from .replay import open_trace

REDACTED = "[REDACTED]"

DEFAULT_KEY_RE = re.compile(
    r"(?i)("
    r"api[_-]?key|secret|token|password|passwd|pwd|auth|bearer|credential|"
    r"private[_-]?key|client[_-]?secret|access[_-]?key|session[_-]?key|"
    r"ssn|social[_-]?security|credit[_-]?card|card[_-]?number"
    r")"
)

_DEFAULT_VALUE_PATTERNS = [
    r"sk-[A-Za-z0-9]{16,}",  # OpenAI-style
    r"sk-ant-[A-Za-z0-9\-_]{16,}",  # Anthropic-style
    r"ghp_[A-Za-z0-9]{20,}",  # GitHub classic PAT
    r"github_pat_[A-Za-z0-9_]{20,}",  # GitHub fine-grained PAT
    r"xox[baprs]-[A-Za-z0-9\-]{10,}",  # Slack tokens
    r"AKIA[0-9A-Z]{16}",  # AWS access key id
    r"AIza[0-9A-Za-z\-_]{30,}",  # Google API key
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----",  # PEM private keys
]

DEFAULT_VALUE_RES = [re.compile(p) for p in _DEFAULT_VALUE_PATTERNS]

# String fields we scan/redact inside event payloads.
_TEXT_FIELDS = ("text", "output", "error", "input")


def _redact_string(value: str, value_res: list[re.Pattern], count: list) -> str:
    def _sub(match: re.Match) -> str:
        count[0] += 1
        return REDACTED

    for pattern in value_res:
        value = pattern.sub(_sub, value)
    return value


def redact_value(
    key: str,
    value,
    key_re: re.Pattern = DEFAULT_KEY_RE,
    value_res: list[re.Pattern] | None = None,
    count: list | None = None,
) -> tuple:
    """Redact a single key/value pair. Returns (new_value, redacted_bool)."""
    if value_res is None:
        value_res = DEFAULT_VALUE_RES
    if count is None:
        count = [0]
    before = count[0]
    if isinstance(key, str) and key_re.search(key):
        if value != REDACTED:
            count[0] += 1
        return REDACTED, count[0] > before
    if isinstance(value, str):
        value = _redact_string(value, value_res, count)
    elif isinstance(value, dict):
        value = {
            k: redact_value(k, v, key_re, value_res, count)[0] for k, v in value.items()
        }
    elif isinstance(value, (list, tuple)):
        value = [redact_value("", item, key_re, value_res, count)[0] for item in value]
    return value, count[0] > before


def redact_event(
    event: dict,
    key_re: re.Pattern = DEFAULT_KEY_RE,
    value_res: list[re.Pattern] | None = None,
) -> tuple[dict, int]:
    """Return (redacted_event, number_of_redactions). Never mutates input."""
    if value_res is None:
        value_res = DEFAULT_VALUE_RES
    count = [0]
    redacted = {
        k: redact_value(k, v, key_re, value_res, count)[0] for k, v in event.items()
    }
    return redacted, count[0]


# ---------------------------------------------------------------------------
# Scanning an existing trace file
# ---------------------------------------------------------------------------


class Finding:
    """One suspicious value found by ``scan_file``."""

    def __init__(self, line_no: int, field: str, preview: str, reason: str):
        self.line_no = line_no
        self.field = field
        self.preview = preview
        self.reason = reason

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return (
            f"Finding(line={self.line_no}, field={self.field!r}, "
            f"preview={self.preview!r}, reason={self.reason!r})"
        )


def _masked(value: str, keep: int = 4) -> str:
    value = str(value)
    if len(value) <= keep + 3:
        return "***"
    return value[:keep] + "***"


def _walk(
    obj,
    path: str,
    findings: list,
    line_no: int,
    value_res: list[re.Pattern],
    key_re: re.Pattern,
) -> None:
    if isinstance(obj, dict):
        for key, val in obj.items():
            p = f"{path}.{key}" if path else str(key)
            if isinstance(key, str) and key_re.search(key):
                if isinstance(val, str) and val != REDACTED and val.strip():
                    findings.append(
                        Finding(line_no, p, _masked(val), f"sensitive key name {key!r}")
                    )
                elif val is not None and val != REDACTED and val not in ("", [], {}):
                    # A structured value under a sensitive key (e.g. a
                    # "credentials" dict) may itself hold secrets; flag it
                    # without printing its contents.
                    findings.append(
                        Finding(
                            line_no,
                            p,
                            "(structured value)",
                            f"sensitive key name {key!r} — contents not shown",
                        )
                    )
                continue  # don't descend into an already-flagged secret
            _walk(val, p, findings, line_no, value_res, key_re)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk(item, f"{path}[{i}]", findings, line_no, value_res, key_re)
    elif isinstance(obj, str):
        for pattern in value_res:
            match = pattern.search(obj)
            if match:
                findings.append(
                    Finding(
                        line_no,
                        path,
                        _masked(match.group(0)),
                        f"matches secret pattern {pattern.pattern!r}",
                    )
                )
                break


def scan_file(
    path: str,
    key_re: re.Pattern = DEFAULT_KEY_RE,
    value_res: list[re.Pattern] | None = None,
) -> list[Finding]:
    """Scan a JSONL trace for likely secrets. Handles ``.gz`` transparently."""
    if value_res is None:
        value_res = DEFAULT_VALUE_RES
    findings: list[Finding] = []
    with open_trace(path) as handle:
        for line_no, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            _walk(event, "", findings, line_no, value_res, key_re)
    return findings


def redact_file(
    src: str,
    dst: str,
    key_re: re.Pattern = DEFAULT_KEY_RE,
    value_res: list[re.Pattern] | None = None,
) -> dict:
    """Copy a trace with redaction applied. Returns stats dict."""
    if value_res is None:
        value_res = DEFAULT_VALUE_RES

    total_redactions = 0
    events = 0
    opener = gzip.open if dst.endswith(".gz") else open
    with open_trace(src) as handle, opener(dst, "wt", encoding="utf-8") as out:
        for line in handle:
            stripped = line.strip()
            if not stripped:
                continue
            event = json.loads(stripped)
            redacted, n = redact_event(event, key_re, value_res)
            total_redactions += n
            events += 1
            out.write(json.dumps(redacted) + "\n")
    return {"events": events, "redactions": total_redactions, "dst": dst}
