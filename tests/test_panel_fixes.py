"""Regression tests for the synapse-1 panel review (findings #1-#10)."""

import asyncio
import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg import CheckRules, Recorder, Session, run_check  # noqa: E402
from redbg._text import clean  # noqa: E402
from redbg.cli import export_markdown, main  # noqa: E402
from redbg.diff import normalize_args  # noqa: E402
from redbg.redact import redact_event, redact_file, scan_file  # noqa: E402
from redbg.schema import TOO_DEEP  # noqa: E402

PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIIEpAIBAAKCAQEA1z9TOTALLYFAKEBODYLINEONE\n"
    "q8pXnZ2PRETENDSECONDLINEOFKEYMATERIAL0123\n"
    "-----END RSA PRIVATE KEY-----"
)
ENV = "OPENAI_API_KEY=abc123def456ghi789jkl\nDB_PASSWORD=hunter2\nDEBUG=true\n"


def _out(text):
    return redact_event({"type": "x", "output": text})[0]["output"]


def _raw_trace(tmp_path, output):
    """Record with redaction OFF, as the reviewer did (`cat .env` output)."""
    path = str(tmp_path / "raw.jsonl")
    with Recorder(path, redact=False) as rec:
        c = rec.tool_call("shell", {"cmd": "cat .env"})
        rec.tool_result(c, ok=True, output=output)
    return path


# -- #1 free-text secrets ----------------------------------------------------


def test_1_env_lines_and_full_pem_block_redacted_and_scan_agrees(tmp_path):
    raw = _raw_trace(tmp_path, ENV + PEM + "\ntrailing text")
    assert scan_file(raw), "scan must flag the raw trace"
    red = str(tmp_path / "red.jsonl")
    redact_file(raw, red)
    text = open(red).read()
    for leaked in ("abc123def456ghi789jkl", "hunter2", "MIIEpA", "PRETEND", "END RSA"):
        assert leaked not in text, leaked
    assert "OPENAI_API_KEY=[REDACTED]" in text  # key name kept for debugging
    assert "DEBUG=true" in text and "trailing text" in text
    assert scan_file(red) == []


def test_1_truncated_pem_redacted_to_end():
    out = _out("x\n" + PEM.split("-----END")[0])
    assert "MIIEpA" not in out and out.startswith("x\n")


@pytest.mark.parametrize(
    "text, leaked",
    [
        ("GET /v1/x?api_key=abcd1234efgh&q=cats", "abcd1234efgh"),
        ("https://h/x?q=1&access_token=zz99yy88xx", "zz99yy88xx"),
        ("Authorization: Basic Zm9vOmJhcjEyMw==", "Zm9vOmJhcjEyMw=="),
        ("Authorization: Bearer  abcdef123456789xyz", "abcdef123456789xyz"),
        ("Authorization: Bearer\tabcdef123456789xyz", "abcdef123456789xyz"),
        ("Bearer:abcdef123456789xyz", "abcdef123456789xyz"),
        ('export SECRET_KEY="s3cr3tvalue"', "s3cr3tvalue"),
        ("password: correct-horse-9", "correct-horse-9"),
        ("DB_PWD=letmein99", "letmein99"),
        ('{"client_secret": "cs_8f7e6d5c"}', "cs_8f7e6d5c"),
    ],
)
def test_1_more_free_text_shapes(text, leaked):
    out = _out(text)
    assert leaked not in out
    assert "[REDACTED]" in out


@pytest.mark.parametrize(
    "text",
    [
        "the bearer of this letter has basic functionality",
        "password reset requested by user",
        "token limit exceeded for request",
        "max_tokens=1024 prompt_tokens: 12",
        "see https://example.com/path@v2",
        "PWD=/home/dan\nOLDPWD=/tmp",
    ],
)
def test_1_prose_and_counts_survive(text):
    assert _out(text) == text


def test_1_redaction_stays_linear_on_hostile_input():
    import time

    payloads = [
        "x" * 200_000,
        "a-" * 100_000,
        "token" * 40_000,
        "a" * 60 + "token" * 30_000 + "=",
        "-----BEGIN RSA PRIVATE KEY-----" * 20_000,
        "basic " * 50_000 + "1",
        "bearer:" * 50_000,
    ]
    start = time.perf_counter()
    for p in payloads:
        _out(p)
    assert time.perf_counter() - start < 3.0


# -- #2 empty / garbage traces ----------------------------------------------


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text)
    return str(p)


def test_2_empty_trace_fails_check(tmp_path, capsys):
    empty = _write(tmp_path, "empty.jsonl", "")
    assert main(["check", empty, "--allow-incomplete"]) == 1
    assert "no tool steps" in capsys.readouterr().out
    assert main(["check", empty, "--allow-incomplete", "--allow-empty"]) == 0


def test_2_garbage_trace_fails_check(tmp_path):
    garbage = _write(tmp_path, "g.jsonl", "not json\n{also not\n")
    assert (
        main(
            [
                "check",
                garbage,
                "--skip-bad",
                "--allow-incomplete",
                "--max-steps",
                "0",
            ]
        )
        == 1
    )


def test_2_no_rules_checked_fails(trace_ok):
    result = run_check(Session.load(trace_ok), CheckRules(require_complete=False))
    assert [v.rule for v in result.violations] == ["no_rules"]
    assert run_check(
        Session.load(trace_ok), CheckRules(require_complete=False, allow_empty=True)
    ).passed


# -- #3 deep nesting ----------------------------------------------------------


def _deep_trace(tmp_path, depth=900):
    args = "[" * depth + "]" * depth
    lines = [
        '{"v":1,"id":"s","ts":"t","mono":0,"type":"session_start","agent":"a"}',
        '{"v":1,"id":"c1","ts":"t","mono":0,"type":"tool_call","step":1,'
        f'"tool":"t","args":{{"x":{args}}}}}',
        '{"v":1,"id":"r1","ts":"t","mono":1,"type":"tool_result","step":1,'
        '"call_id":"c1","tool":"t","ok":true,"output":"o"}',
        '{"v":1,"id":"e","ts":"t","mono":2,"type":"session_end","status":"ok"}',
    ]
    return _write(tmp_path, "deep.jsonl", "\n".join(lines) + "\n")


def test_3_normalize_uses_constant_marker():
    deep: list = []
    cur = deep
    for _ in range(5000):
        nxt: list = []
        cur.append(nxt)
        cur = nxt
    out = normalize_args(deep)
    while isinstance(out, list) and out:
        out = out[0]
    assert out == TOO_DEEP


@pytest.mark.parametrize("cmd", ["check", "diff", "info", "scan"])
def test_3_deep_trace_never_tracebacks(tmp_path, capsys, cmd):
    path = _deep_trace(tmp_path)
    argv = [cmd, path] + (["--baseline", path] if cmd == "check" else [])
    argv += [path] if cmd == "diff" else []
    code = main(argv)
    assert code in (0, 1, 2)
    if cmd == "check":
        assert code in (0, 2)  # never "1 = violations" for a crash


def test_3_unparseably_deep_json_exits_2(tmp_path, capsys):
    depth = 200_000
    line = '{"v":1,"id":"c","ts":"t","mono":0,"type":"note","text":"x","d":'
    path = _write(tmp_path, "d.jsonl", line + "[" * depth + "]" * depth + "}\n")
    assert main(["check", path]) == 2
    assert "nested too deeply" in capsys.readouterr().err


def test_3_recorder_and_redactor_survive_deep_args(tmp_path):
    deep: dict = {}
    cur = deep
    for _ in range(3000):
        cur["k"] = {}
        cur = cur["k"]
    path = str(tmp_path / "s.jsonl")
    with Recorder(path) as rec:
        c = rec.tool_call("t", deep)
        rec.tool_result(c, ok=True, output=deep)
    assert len(Session.load(path).steps) == 1
    _, n = redact_event({"type": "x", "args": deep})
    assert n >= 1  # deep subtree fails closed (redacted, not leaked)


# -- #4 unicode spoofing ------------------------------------------------------


@pytest.mark.parametrize("ch", ["‮", "⁦", "⁩", "​", "‍", "﻿", " ", " "])
def test_4_invisible_and_bidi_chars_escaped(ch):
    out = clean(f"a{ch}b")
    assert ch not in out
    assert f"\\u{ord(ch):04x}" in out


def test_4_spoofed_tool_name_visible_everywhere(tmp_path, capsys):
    path = str(tmp_path / "s.jsonl")
    spoof = "‮elif_daer"
    with Recorder(path) as rec:
        c = rec.tool_call(spoof, {"p": "⁦x⁩"})
        rec.tool_result(c, ok=True, output="o p")
    for argv in (
        ["replay", path, "--list", "--no-color"],
        ["replay", path, "--show", "1", "--no-color"],
        ["diff", path, path, "--no-color"],
        ["check", path, "--forbid-tool", "*", "--no-color"],
    ):
        main(argv)
        out = capsys.readouterr().out
        assert "‮" not in out and "⁦" not in out and " " not in out
        assert "\\u202e" in out
    md = export_markdown(Session.load(path))
    assert "‮" not in md and " " not in md


def test_4_normal_unicode_untouched():
    assert clean("中文 ünï ✓ é") == "中文 ünï ✓ é"


# -- #5 non-string tool names -------------------------------------------------


@pytest.mark.parametrize("tool", ["123", "null", "[1]", '{"a":1}'])
def test_5_non_string_tool_name(tmp_path, capsys, tool):
    path = _write(
        tmp_path,
        "t.jsonl",
        '{"v":1,"id":"s","ts":"t","mono":0,"type":"session_start","agent":"a"}\n'
        f'{{"v":1,"id":"c","ts":"t","mono":0,"type":"tool_call","step":1,'
        f'"tool":{tool},"args":{{}}}}\n'
        '{"v":1,"id":"r","ts":"t","mono":1,"type":"tool_result","step":1,'
        f'"call_id":"c","tool":{tool},"ok":true}}\n'
        '{"v":1,"id":"e","ts":"t","mono":2,"type":"session_end","status":"ok"}\n',
    )
    step = Session.load(path).steps[0]
    assert isinstance(step.tool, str)
    assert main(["check", path, "--forbid-tool", "x*", "--require-tool", "*"]) == 0
    assert main(["diff", path, path, "--no-color"]) == 0
    assert main(["info", path, "--no-color"]) == 0


# -- #6 is covered in test_check.py (test_forbid_matches_normalized_names) ----


# -- #7 async callables and generators ---------------------------------------


def test_7_async_dunder_call_object(tmp_path):
    class Fetcher:
        async def __call__(self, url):
            await asyncio.sleep(0)
            return f"body of {url}"

    path = str(tmp_path / "s.jsonl")
    with Recorder(path) as rec:
        fetch = rec.wrap(Fetcher(), name="fetch")
        assert asyncio.run(fetch("u")) == "body of u"
        unnamed = rec.wrap(Fetcher())
        asyncio.run(unnamed("v"))
    steps = Session.load(path).steps
    assert steps[0].output == "body of u"
    assert steps[1].tool == "Fetcher"
    assert all("coroutine" not in (s.output or "") for s in steps)


def test_7_generators_rejected_clearly(tmp_path):
    with Recorder(str(tmp_path / "s.jsonl")) as rec:

        async def agen():
            yield 1

        def gen():
            yield 1

        class AGenCall:
            async def __call__(self):
                yield 1

        for fn in (agen, gen, AGenCall()):
            with pytest.raises(TypeError, match="generator"):
                rec.wrap(fn)


# -- #8 redaction precision ---------------------------------------------------


def test_8_usage_details_and_string_counts_kept():
    usage = {
        "max_tokens": "1024",
        "totalTokenCount": 9,
        "usage": {
            "completion_tokens_details": {"reasoning_tokens": 5},
            "prompt_tokens_details": {"cached_tokens": 2, "audio_tokens": 0},
        },
    }
    out, n = redact_event({"type": "x", **usage})
    assert n == 0
    assert {k: out[k] for k in usage} == usage


def test_8_secrets_inside_details_or_strong_keys_still_redacted():
    out, _ = redact_event(
        {
            "type": "x",
            "secret_tokens": 123456,
            "access_token_count": 42,
            "prompt_tokens_details": {"api_key": "plainvalue"},
            "secret_tokens_details": {"a": 1},
            "max_tokens": "sk-abcdefghijklmnopqrstu",
        }
    )
    assert out["secret_tokens"] == "[REDACTED]"
    assert out["access_token_count"] == "[REDACTED]"
    assert out["prompt_tokens_details"]["api_key"] == "[REDACTED]"
    assert out["secret_tokens_details"] == "[REDACTED]"
    assert out["max_tokens"] == "[REDACTED]"


# -- #9 fork --save overwrite -------------------------------------------------


def test_9_fork_save_refuses_to_overwrite_source(trace_ok, capsys):
    before = open(trace_ok).read()
    assert main(["fork", trace_ok, "--at", "1", "--save", trace_ok]) == 2
    assert "refusing to overwrite" in capsys.readouterr().err
    assert open(trace_ok).read() == before


def test_9_fork_save_elsewhere_still_works(trace_ok, tmp_path):
    dst = str(tmp_path / "fork.jsonl")
    assert main(["fork", trace_ok, "--at", "1", "--save", dst]) == 0
    assert json.loads(open(dst).readline())["meta"]["fork"] is True


# -- #10 bare `pytest` collection ---------------------------------------------


def test_10_tests_do_not_import_tests_package():
    here = os.path.dirname(__file__)
    for name in os.listdir(here):
        if name.endswith(".py") and name != os.path.basename(__file__):
            with open(os.path.join(here, name), encoding="utf-8") as fh:
                assert "from tests." not in fh.read(), name


def test_10_bare_pytest_collects(tmp_path):
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    # Run the pytest entry point (not `python -m pytest`, which adds the CWD to
    # sys.path and hid the bug) from the repo root, collection only.
    code = (
        "import sys, pytest; sys.path[:] = [p for p in sys.path if p not in ('', '.')];"
        f"sys.exit(pytest.main(['--collect-only', '-q', '-p', 'no:cacheprovider', "
        f"{os.path.join(root, 'tests')!r}]))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
