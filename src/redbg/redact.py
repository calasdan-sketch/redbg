"""Secrets redaction for redbg traces.

Two jobs:
1. ``redact_event`` — applied at record time (and by ``redbg redact``) to strip
   secrets from a trace before it is written or shared.
2. ``scan_file`` — audits an existing trace for values that *look* secret but
   were not redacted, so you can check before sharing.

Redaction is structural: values of keys whose names look sensitive are
replaced wholesale, and substrings matching known secret shapes (provider
token formats, PEM blocks, ``Authorization`` values, URL credentials and
``KEY=value`` assignments) are replaced wherever they appear in strings.
This is a pattern-based safety net, not a guarantee.
"""

from __future__ import annotations

import gzip
import json
import re

from .replay import ensure_distinct, open_trace
from .schema import MAX_NESTING

REDACTED = "[REDACTED]"

DEFAULT_KEY_RE = re.compile(
    r"(?i)("
    # "auth" but not "author"/"authority" (still matches "authorization").
    r"api[_-]?key|secret|token|password|passwd|pwd|auth(?!or(?!iz))|bearer|"
    r"credential|"
    r"private[_-]?key|client[_-]?secret|access[_-]?key|session[_-]?key|"
    r"ssn|social[_-]?security|credit[_-]?card|card[_-]?number"
    r")"
)

# Key names that look sensitive but only *count* tokens (LLM usage fields
# like ``max_tokens``, ``prompt_tokens``, ``totalTokenCount``,
# ``token_count``). Their value is exempt from key-name redaction when — and
# only when — it is a plain number (or a digit-only string): redacting usage
# made cost/latency debugging impossible, and a count is not a credential.
_COUNT_KEY_RE = re.compile(r"(?i)(?:tokens|tokens?[_-]?(?:count|used|limit|usage))$")
# ``completion_tokens_details`` / ``prompt_tokens_details`` dicts: descend
# into them (each inner field is judged on its own) instead of blanking.
_DETAILS_KEY_RE = re.compile(r"(?i)tokens?[_-]?details$")
# A key containing one of these is never exempt (``secret_tokens``,
# ``api_key_tokens``, ``access_token_count``...).
_STRONG_KEY_RE = re.compile(
    r"(?i)secret|passw|pwd|api[_-]?key|auth(?!or(?!iz))|bearer|credential|"
    r"private|access|refresh|session|client|id[_-]?token|csrf|xsrf"
)
_DIGITS_RE = re.compile(r"\d{1,15}")
# Free-text keys that merely look sensitive: the shell's working-directory
# variables in env dumps (``PWD=/home/dan``). ``DB_PWD=`` is still redacted.
_BENIGN_ASSIGN_KEY_RE = re.compile(r"(?i)(?:old)?pwd")

# The value side of a ``KEY=value`` / ``KEY: value`` / ``?key=value`` line.
_ASSIGN_KEYS = (
    r"api[_-]?key|apikey|secret|token|passw(?:or)?d|passwd|pwd|credential|"
    r"private[_-]?key|access[_-]?key|client[_-]?secret|session[_-]?key"
)

_DEFAULT_VALUE_PATTERNS = [
    r"sk-[A-Za-z0-9]{16,}",  # OpenAI-style (legacy)
    r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9\-_]{16,}",  # OpenAI project/service
    r"sk-ant-[A-Za-z0-9\-_]{16,}",  # Anthropic-style
    r"gh[pousr]_[A-Za-z0-9]{20,}",  # GitHub PAT / OAuth / app tokens
    r"github_pat_[A-Za-z0-9_]{20,}",  # GitHub fine-grained PAT
    r"xox[baprs]-[A-Za-z0-9\-]{10,}",  # Slack tokens
    r"https://hooks\.slack\.com/services/[A-Za-z0-9/_\-]{20,}",  # Slack webhook
    r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}",  # Stripe secret/restricted
    r"AKIA[0-9A-Z]{16}",  # AWS access key id
    r"AIza[0-9A-Za-z\-_]{30,}",  # Google API key
    r"hf_[A-Za-z0-9]{30,}",  # Hugging Face token
    r"eyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}",  # JWT
    # The whole PEM private-key block (body included). An unterminated block
    # (truncated output) is redacted to the end of the string.
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?"
    r"(?:-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----|\Z)",
    # Authorization: Bearer <tok> / Bearer:<tok> / any whitespace. The token
    # must contain a digit, so prose ("the bearer of this letter") survives.
    r"(?i)\bbearer[\s:]+(?P<secret>(?=[A-Za-z\-._~+/]*\d)[A-Za-z0-9\-._~+/]{8,}=*)",
    # Authorization: Basic <base64>. Must contain a digit or + / =.
    r"(?i)\bbasic[\s:]+(?P<secret>(?=[A-Za-z]*[0-9+/=])[A-Za-z0-9+/]{8,}={0,2})"
    r"(?![A-Za-z0-9+/=])",
    # user:password@host in URLs.
    r"(?<=://)(?P<secret>[^/\s:@]{1,256}:[^/\s@]{1,256})(?=@)",
    # Free-text assignments: .env lines, `export X=`, YAML/HTTP-header style
    # `X: y`, JSON-ish `"x": "y"`, and query strings (`?api_key=...&`).
    # Bounded, start-anchored key name keeps this linear on huge inputs.
    r"(?i)(?<![A-Za-z0-9_.\-])"
    r"(?P<key>[A-Za-z0-9_.\-]{0,64}?(?:" + _ASSIGN_KEYS + r")[A-Za-z0-9_.\-]{0,64})"
    r"[\"']?[ \t]*[=:][ \t]*[\"']?(?!\[REDACTED\])"
    r"(?P<secret>[^\s\"'&,;<>]{4,})",
]

DEFAULT_VALUE_RES = [re.compile(p) for p in _DEFAULT_VALUE_PATTERNS]

# String fields we scan/redact inside event payloads.
_TEXT_FIELDS = ("text", "output", "error", "input")


def _is_count(key: str, value) -> bool:
    """A usage counter under a token-ish key (``max_tokens: 100``)."""
    if isinstance(value, bool):
        return False
    if isinstance(value, str):
        if not _DIGITS_RE.fullmatch(value):
            return False
    elif not isinstance(value, (int, float)):
        return False
    return bool(_COUNT_KEY_RE.search(key)) and not _STRONG_KEY_RE.search(key)


def _key_policy(key, value, key_re: re.Pattern) -> str | None:
    """How to treat a dict entry: ``"redact"``, or None (inspect normally)."""
    if not isinstance(key, str) or not key_re.search(key):
        return None
    if _is_count(key, value):
        return None
    if (
        isinstance(value, dict)
        and _DETAILS_KEY_RE.search(key)
        and not _STRONG_KEY_RE.search(key)
    ):
        return None  # descend; inner keys are judged individually
    return "redact"


def _secret_spans(pattern: re.Pattern, text: str):
    """Yield (start, end) spans to redact for ``pattern`` in ``text``.

    A pattern with a ``secret`` group redacts only that group (the key name
    or ``Bearer`` prefix stays readable). With a ``key`` group too, matches
    whose key is a usage counter and whose value is a number are skipped
    (``max_tokens=1024`` in a log line is not a secret).
    """
    groups = pattern.groupindex
    for match in pattern.finditer(text):
        if "secret" in groups:
            if "key" in groups and (
                _is_count(match.group("key"), match.group("secret"))
                or _BENIGN_ASSIGN_KEY_RE.fullmatch(match.group("key"))
            ):
                continue
            span = match.span("secret")
        else:
            span = match.span()
        if span[1] > span[0]:
            yield span


def _redact_string(value: str, value_res: list[re.Pattern], count: list) -> str:
    for pattern in value_res:
        spans = list(_secret_spans(pattern, value))
        if not spans:
            continue
        parts = []
        last = 0
        for begin, end in spans:
            parts.append(value[last:begin])
            parts.append(REDACTED)
            last = end
        parts.append(value[last:])
        value = "".join(parts)
        count[0] += len(spans)
    return value


def redact_value(
    key: str,
    value,
    key_re: re.Pattern = DEFAULT_KEY_RE,
    value_res: list[re.Pattern] | None = None,
    count: list | None = None,
    _depth: int = 0,
) -> tuple:
    """Redact a single key/value pair. Returns (new_value, redacted_bool)."""
    if value_res is None:
        value_res = DEFAULT_VALUE_RES
    if count is None:
        count = [0]
    before = count[0]
    if _depth > MAX_NESTING and isinstance(value, (dict, list, tuple)):
        count[0] += 1  # too deep to inspect: fail closed
        return REDACTED, True
    if _key_policy(key, value, key_re) == "redact":
        if value != REDACTED:
            count[0] += 1
        return REDACTED, count[0] > before
    if isinstance(value, str):
        value = _redact_string(value, value_res, count)
    elif isinstance(value, dict):
        value = {
            k: redact_value(k, v, key_re, value_res, count, _depth + 1)[0]
            for k, v in value.items()
        }
    elif isinstance(value, (list, tuple)):
        value = [
            redact_value("", item, key_re, value_res, count, _depth + 1)[0]
            for item in value
        ]
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
    _depth: int = 0,
) -> None:
    if _depth > MAX_NESTING and isinstance(obj, (dict, list)):
        findings.append(
            Finding(line_no, path, "(not shown)", "nested too deeply to scan")
        )
        return
    if isinstance(obj, dict):
        for key, val in obj.items():
            p = f"{path}.{key}" if path else str(key)
            if _key_policy(key, val, key_re) == "redact":
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
            _walk(val, p, findings, line_no, value_res, key_re, _depth + 1)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk(
                item, f"{path}[{i}]", findings, line_no, value_res, key_re, _depth + 1
            )
    elif isinstance(obj, str):
        for pattern in value_res:
            span = next(_secret_spans(pattern, obj), None)
            if span:
                findings.append(
                    Finding(
                        line_no,
                        path,
                        _masked(obj[span[0] : span[1]]),
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

    ensure_distinct(src, dst)
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
