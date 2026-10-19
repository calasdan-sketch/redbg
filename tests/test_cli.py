import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg.cli import main  # noqa: E402


def test_info_reports_session_summary(trace_ok, capsys):
    assert main(["info", trace_ok, "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "steps:      2" in out
    assert "read_file" in out


def test_info_missing_file_returns_2(capsys):
    assert main(["info", "/nope.jsonl"]) == 2


def test_diff_reports_divergence(trace_ok, trace_fail, capsys):
    assert main(["diff", trace_ok, trace_fail, "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "First divergence" in out
    assert "A: 2 steps · B: 3 steps" in out


def test_diff_identical(trace_ok, capsys):
    assert main(["diff", trace_ok, trace_ok, "--no-color"]) == 0
    assert "identical" in capsys.readouterr().out


def test_scan_clean_trace(trace_ok, capsys):
    assert main(["scan", trace_ok]) == 0
    assert "clean" in capsys.readouterr().out


def test_scan_finds_secret_and_exits_1(tmp_path, capsys):
    path = tmp_path / "s.jsonl"
    path.write_text(
        '{"v":1,"id":"a","ts":"t","mono":0,"type":"tool_call","step":1,'
        '"tool":"t","args":{"api_key":"supersecret123"}}\n'
    )
    assert main(["scan", str(path)]) == 1
    out = capsys.readouterr().out
    assert "supersecret123" not in out  # masked preview
    assert "api_key" in out


def test_redact_command(tmp_path, capsys):
    src = tmp_path / "in.jsonl"
    dst = tmp_path / "out.jsonl"
    src.write_text(
        '{"v":1,"id":"a","ts":"t","mono":0,"type":"tool_call","step":1,'
        '"tool":"t","args":{"password":"pw"}}\n'
    )
    assert main(["redact", str(src), "-o", str(dst)]) == 0
    assert "1 value(s)" in capsys.readouterr().out
    assert '"password": "[REDACTED]"' in dst.read_text()


def test_replay_list_and_show(trace_ok, capsys):
    assert main(["replay", trace_ok, "--list", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "read_file" in out and "write_file" in out

    assert main(["replay", trace_ok, "--show", "1", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "step 1/2" in out
    assert "a.txt" in out


def test_replay_scripted_commands(trace_ok, capsys):
    assert main(["replay", trace_ok, "--cmd", "n;n;p;l", "--no-color"]) == 0
    out = capsys.readouterr().out
    assert "step 1/2" in out and "step 2/2" in out


def test_replay_export_md(trace_ok, tmp_path):
    out = tmp_path / "report.md"
    assert main(["replay", trace_ok, "--export-md", str(out), "--no-color"]) == 0
    text = out.read_text()
    assert "## step 1: `read_file`" in text
    assert "## step 2: `write_file`" in text


def test_fork_command_saves_trace(trace_fail, tmp_path):
    out = tmp_path / "fork.jsonl"
    tools_py = tmp_path / "tools.py"
    tools_py.write_text(
        "TOOLS = {'read_file': lambda args: 'real:' + args['path'],\n"
        "         'write_file': lambda args: 'wrote'}\n"
    )
    rc = main(
        [
            "fork",
            trace_fail,
            "--at",
            "1",
            "--override-args",
            '{"path": "fixed.txt"}',
            "--tools",
            str(tools_py),
            "--save",
            str(out),
        ]
    )
    assert rc == 0
    data = out.read_text()
    assert "fixed.txt" in data
    assert '"fork": true' in data


def test_fork_bad_json_override(trace_fail, capsys):
    rc = main(["fork", trace_fail, "--at", "1", "--override-args", "{bad json"])
    assert rc == 2
    assert "bad --override-args JSON" in capsys.readouterr().err


def test_import_command(tmp_path, capsys):
    src = tmp_path / "spans.json"
    dst = tmp_path / "out.jsonl"
    src.write_text(
        json.dumps(
            [
                {
                    "name": "tool.echo",
                    "attributes": {"tool.args": {"a": 1}, "tool.output": "ok"},
                },
            ]
        )
    )
    assert main(["import", str(src), "-o", str(dst)]) == 0
    out = capsys.readouterr().out
    assert "1 tool steps" in out
    assert "heuristic" in out


def test_unknown_replay_command_handled(trace_ok, capsys):
    assert main(["replay", trace_ok, "--cmd", "frobnicate", "--no-color"]) == 0
    assert "unknown command" in capsys.readouterr().out
