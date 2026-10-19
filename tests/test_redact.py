import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg.redact import (  # noqa: E402
    REDACTED,
    redact_event,
    redact_file,
    scan_file,
)
from redbg.replay import load_events  # noqa: E402


def _ev(**fields):
    base = {
        "v": 1,
        "id": "x",
        "ts": "t",
        "mono": 0.0,
        "type": "tool_call",
        "step": 1,
        "tool": "t",
        "args": {},
    }
    base.update(fields)
    return base


def test_redact_event_key_patterns():
    event = _ev(args={"api_key": "abc", "password": "hunter2", "path": "/tmp/x"})
    redacted, n = redact_event(event)
    assert redacted["args"]["api_key"] == REDACTED
    assert redacted["args"]["password"] == REDACTED
    assert redacted["args"]["path"] == "/tmp/x"
    assert n == 2


def test_redact_event_nested_and_lists():
    event = _ev(
        args={
            "config": {"auth": {"token": "tok123"}},
            "items": [{"secret": "s1"}, "plain"],
        }
    )
    redacted, n = redact_event(event)
    assert redacted["args"]["config"] == {"auth": REDACTED}  # wholesale: the
    # whole "auth" object is sensitive, not just the token inside it
    assert redacted["args"]["items"][0]["secret"] == REDACTED
    assert redacted["args"]["items"][1] == "plain"
    assert n == 2


def test_redact_event_value_patterns():
    event = _ev(args={"note": "key is sk-abcdefghijklmnop1234 ok"})
    redacted, n = redact_event(event)
    assert "sk-abcdefghijklmnop1234" not in redacted["args"]["note"]
    assert REDACTED in redacted["args"]["note"]
    assert n == 1


def test_redact_event_does_not_mutate_input():
    event = _ev(args={"api_key": "abc"})
    redact_event(event)
    assert event["args"]["api_key"] == "abc"


def test_redact_file(tmp_path):
    src = tmp_path / "in.jsonl"
    dst = tmp_path / "out.jsonl"
    src.write_text(
        '{"v":1,"id":"a","ts":"t","mono":0,"type":"tool_call","step":1,'
        '"tool":"t","args":{"password":"pw"}}\n'
        '{"v":1,"id":"b","ts":"t","mono":0,"type":"tool_call","step":2,'
        '"tool":"t","args":{"path":"/x"}}\n'
    )
    stats = redact_file(str(src), str(dst))
    assert stats == {"events": 2, "redactions": 1, "dst": str(dst)}
    events = load_events(str(dst))
    assert events[0]["args"]["password"] == REDACTED
    assert events[1]["args"]["path"] == "/x"


def test_scan_file_finds_planted_secrets(tmp_path):
    path = tmp_path / "s.jsonl"
    path.write_text(
        '{"v":1,"id":"a","ts":"t","mono":0,"type":"tool_call","step":1,'
        '"tool":"t","args":{"api_key":"supersecretvalue"}}\n'
        '{"v":1,"id":"b","ts":"t","mono":0,"type":"response",'
        '"text":"here is sk-abcdefghijklmnop1234 in prose"}\n'
    )
    findings = scan_file(str(path))
    assert len(findings) == 2
    assert any("api_key" in f.reason for f in findings)
    assert any("secret pattern" in f.reason for f in findings)
    # Previews must be masked, not raw secrets.
    for finding in findings:
        assert "supersecretvalue" not in finding.preview
        assert "sk-abcdefghijklmnop1234" not in finding.preview


def test_scan_file_clean_passes_and_ignores_redacted(tmp_path):
    path = tmp_path / "s.jsonl"
    path.write_text(
        '{"v":1,"id":"a","ts":"t","mono":0,"type":"tool_call","step":1,'
        '"tool":"read","args":{"path":"/tmp/x","api_key":"[REDACTED]"}}\n'
    )
    assert scan_file(str(path)) == []


def test_scan_flags_structured_value_under_sensitive_key(tmp_path):
    """A secret dict nested under e.g. 'credentials' must not slip past scan."""
    import json as _json

    from redbg.redact import scan_file

    path = str(tmp_path / "nested.jsonl")
    with open(path, "w") as fh:
        fh.write(
            _json.dumps(
                {
                    "v": 1,
                    "id": "a",
                    "ts": "t",
                    "mono": 0.0,
                    "type": "tool_result",
                    "credentials": {"api_key": "sk-secret-not-really"},
                }
            )
            + "\n"
        )
    findings = scan_file(path)
    assert len(findings) == 1
    assert "credentials" in findings[0].reason
    assert "sk-secret" not in findings[0].preview  # contents not printed
