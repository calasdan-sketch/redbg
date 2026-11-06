"""Security and correctness hardening (0.2.0)."""

import asyncio
import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg import Recorder, Session  # noqa: E402
from redbg._text import clean, md_fence  # noqa: E402
from redbg.cli import export_markdown, main  # noqa: E402
from redbg.diff import render_diff  # noqa: E402
from redbg.importer import import_file  # noqa: E402
from redbg.redact import redact_event, redact_file, scan_file  # noqa: E402

ESC_TOOL = "evil\x1b]0;pwned\x07\x1b[2J\x9b31m\rX"


def _evil_trace(tmp_path):
    path = tmp_path / "evil.jsonl"
    with Recorder(str(path), agent="a\x1b[31m") as rec:
        c = rec.tool_call(ESC_TOOL, {"k": "v\x9b"})
        rec.tool_result(c, ok=False, output="out\x1b[1A", error="err\x1b[K")
    return str(path)


# -- terminal escape injection ----------------------------------------------


def test_clean_escapes_controls_but_keeps_newlines():
    assert clean("a\x1b[2Jb") == "a\\x1b[2Jb"
    assert clean("x\x9by") == "x\\x9by"
    assert clean("a\rb") == "a\\x0db"
    assert clean("l1\n\tl2") == "l1\n\tl2"
    assert clean("ünïcode ✓") == "ünïcode ✓"
    assert clean(None) == "None"


@pytest.mark.parametrize(
    "argv",
    [
        ["replay", "{p}", "--list", "--no-color"],
        ["replay", "{p}", "--show", "1", "--no-color"],
        ["replay", "{p}", "--cmd", "n;s;l;i", "--no-color"],
        ["info", "{p}", "--no-color"],
        ["diff", "{p}", "{p}", "--no-color"],
        ["check", "{p}", "--forbid-tool", "evil*", "--no-color"],
    ],
)
def test_no_raw_control_chars_reach_stdout(tmp_path, capsys, argv):
    path = _evil_trace(tmp_path)
    main([a.replace("{p}", path) for a in argv])
    out = capsys.readouterr().out
    assert "\x1b" not in out and "\x9b" not in out and "\r" not in out
    assert "\x07" not in out


def test_render_diff_sanitizes(tmp_path):
    path = _evil_trace(tmp_path)
    other = tmp_path / "o.jsonl"
    with Recorder(str(other)) as rec:
        c = rec.tool_call("fine", {})
        rec.tool_result(c, ok=True, output="x")
    out = render_diff(Session.load(path), Session.load(str(other)), use_color=False)
    assert "\x1b" not in out and "\x9b" not in out


# -- markdown injection -----------------------------------------------------


def test_md_fence_cannot_be_closed_by_content():
    body = "before\n```\n<script>x</script>\n````\nafter"
    fenced = md_fence(body)
    assert fenced.startswith("`````\n") and fenced.endswith("\n`````")


def test_export_markdown_contains_untrusted_output(tmp_path):
    path = tmp_path / "s.jsonl"
    with Recorder(str(path)) as rec:
        c = rec.tool_call("t`ool", {"a": "```"})
        rec.tool_result(c, ok=True, output="```\n# injected heading\n```")
    md = export_markdown(Session.load(str(path)))
    assert "\n# injected heading" in md  # present...
    # ...but only inside a fence longer than any run in the content.
    assert "````\n```\n# injected heading\n```\n````" in md
    assert "``t`ool``" in md


# -- in-place overwrite guard ------------------------------------------------


def test_redact_refuses_same_file(trace_ok):
    before = open(trace_ok).read()
    with pytest.raises(ValueError, match="refusing to overwrite"):
        redact_file(trace_ok, trace_ok)
    assert open(trace_ok).read() == before


def test_redact_refuses_same_file_via_other_spelling(trace_ok):
    other = os.path.join(os.path.dirname(trace_ok), ".", os.path.basename(trace_ok))
    with pytest.raises(ValueError):
        redact_file(trace_ok, other)


def test_redact_refuses_symlink_to_source(trace_ok, tmp_path):
    link = tmp_path / "link.jsonl"
    try:
        os.symlink(trace_ok, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks unavailable")
    with pytest.raises(ValueError):
        redact_file(trace_ok, str(link))


def test_cli_redact_same_file_exit_2(trace_ok, capsys):
    assert main(["redact", trace_ok, "-o", trace_ok]) == 2
    assert "refusing" in capsys.readouterr().err
    assert Session.load(trace_ok).steps  # intact


def test_import_refuses_same_file(tmp_path):
    src = tmp_path / "x.json"
    src.write_text(json.dumps([{"name": "tool.read"}]))
    with pytest.raises(ValueError):
        import_file(str(src), str(src))


def test_cli_scan_missing_file_exit_2():
    assert main(["scan", "/definitely/not/here.jsonl"]) == 2


# -- redaction accuracy -----------------------------------------------------


@pytest.mark.parametrize(
    "secret",
    [
        "sk-proj-AbCdEf_123-xyz7890abcdefghij",
        "sk-svcacct-AbCdEf_123-xyz7890abcdefghij",
        "sk" + "_live_abcdefghijklmnop1234",
        "rk" + "_test_abcdefghijklmnop1234",
        "gho_abcdefghijklmnopqrstuvwxyz",
        "ghs_abcdefghijklmnopqrstuvwxyz",
        "hf" + "_abcdefghijklmnopqrstuvwxyzABCDEFGH",
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N",
        "https://hooks.slack.com/" + "services/T000/B000/XXXXXXXXXXXXXXXXXXXX",
    ],
)
def test_new_secret_shapes_redacted(secret):
    event, n = redact_event({"type": "x", "output": f"value: {secret} end"})
    assert secret not in event["output"]
    assert n >= 1


def test_bearer_and_url_credentials_redacted():
    text = (
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz123456\n"
        "postgres://admin:hunter2@db.local/app"
    )
    out = redact_event({"type": "x", "output": text})[0]["output"]
    assert "abcdefghijklmnopqrstuvwxyz123456" not in out
    assert "hunter2" not in out
    assert "Bearer [REDACTED]" in out  # header name kept for debugging
    assert "@db.local/app" in out


def test_token_counts_and_author_not_redacted():
    event = {
        "type": "x",
        "args": {
            "max_tokens": 1024,
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "token_count": 15},
            "author": "Dan",
            "authority": "x",
        },
    }
    out, n = redact_event(event)
    assert out["args"] == event["args"]
    assert n == 0


def test_secret_shaped_values_under_count_keys_still_redacted():
    out, _ = redact_event(
        {
            "type": "x",
            "args": {
                "max_tokens": "sk-abcdefghijklmnopqrstu",  # string: not a count
                "token": 123456,  # singular token: could be an OTP
                "authorization": "Basic Zm9vOmJhcg==",
                "card_number": 4111111111111111,
            },
        }
    )
    assert out["args"]["max_tokens"] == "[REDACTED]"
    assert out["args"]["token"] == "[REDACTED]"
    assert out["args"]["authorization"] == "[REDACTED]"
    assert out["args"]["card_number"] == "[REDACTED]"


def test_scan_ignores_token_counts(tmp_path):
    path = tmp_path / "s.jsonl"
    path.write_text(
        '{"v":1,"id":"a","ts":"t","mono":0,"type":"response","text":"hi",'
        '"usage":{"input_tokens":12,"output_tokens":3}}\n'
    )
    assert scan_file(str(path)) == []


def test_redaction_regexes_are_not_catastrophic():
    import time

    payloads = [
        "://" + "a" * 50_000,
        "://" + "a:" * 25_000,
        "bearer " + "a" * 100_000,
        "eyJ" + "a" * 50_000 + ".",
        "x" * 200_000,
    ]
    start = time.perf_counter()
    for p in payloads:
        redact_event({"type": "x", "output": p})
    assert time.perf_counter() - start < 2.0


# -- async tools ------------------------------------------------------------


def test_wrap_async_records_awaited_value(tmp_path):
    path = str(tmp_path / "s.jsonl")
    with Recorder(path) as rec:

        @rec.wrap
        async def fetch(x):
            await asyncio.sleep(0)
            return {"double": x * 2}

        @rec.wrap(name="explode")
        async def bad():
            raise KeyError("nope")

        assert asyncio.run(fetch(21)) == {"double": 42}
        with pytest.raises(KeyError):
            asyncio.run(bad())
    steps = Session.load(path).steps
    assert json.loads(steps[0].output) == {"double": 42}
    assert "coroutine" not in steps[0].output
    assert steps[1].tool == "explode" and steps[1].ok is False
    assert "KeyError" in steps[1].error


def test_wrap_async_concurrent_gather(tmp_path):
    path = str(tmp_path / "s.jsonl")
    with Recorder(path) as rec:

        @rec.wrap
        async def work(i):
            await asyncio.sleep(0.001 * (5 - i))
            return i

        async def main_():
            return await asyncio.gather(*(work(i) for i in range(5)))

        assert asyncio.run(main_()) == [0, 1, 2, 3, 4]
    steps = Session.load(path).steps
    assert len(steps) == 5
    assert all(s.ok for s in steps)
    # results matched to their own calls despite completing out of order
    assert all(s.output == str(s.args["args"][0]) for s in steps)


def test_wrap_async_preserves_coroutine_function_identity(tmp_path):
    import inspect

    with Recorder(str(tmp_path / "s.jsonl")) as rec:

        @rec.wrap
        async def f():
            return 1

        assert inspect.iscoroutinefunction(f)
        assert f.__name__ == "f"
