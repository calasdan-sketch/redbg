from __future__ import annotations

import json

import pytest
from logs import cc_result, cc_session, cc_use, cc_user, codex_session, write_lines

from redbg import Session
from redbg.analysis import (
    Breakpoint,
    blame,
    effects,
    explain,
    file_ledger,
    run_to_breakpoint,
)
from redbg.cli import Repl, main


def _cc(tmp_path, objs=None):
    return Session.load(write_lines(tmp_path / "c.jsonl", objs or cc_session()))


def test_effects_declared_and_inferred(tmp_path):
    s = _cc(tmp_path)
    assert [(e.kind, e.path, e.how) for e in effects(s.steps[0])] == [
        ("read", "/work/app/main.py", "declared")]
    assert [(e.kind, e.how) for e in effects(s.steps[1])] == [("write", "declared")]
    assert [(e.kind, e.path, e.how) for e in effects(s.steps[2])] == [
        ("write", "/work/app/out.txt", "inferred")]


@pytest.mark.parametrize("cmd,expect", [
    ("rm -rf build/ old.txt", {("delete", "build"), ("delete", "old.txt")}),
    ("mv a.txt b.txt", {("delete", "a.txt"), ("write", "b.txt")}),
    ("cp -r src dst", {("read", "src"), ("write", "dst")}),
    ("echo hi | tee -a log.txt", {("write", "log.txt")}),
    ("sed -i 's/a/b/' cfg.ini", {("write", "cfg.ini")}),
    ("echo x >> notes.md && ls", {("write", "notes.md")}),
    ("cmd 2>/dev/null", set()),
    ("echo $HOME > $OUT", set()),
    ("echo 'unterminated", set()),
])
def test_shell_effects(tmp_path, cmd, expect):
    objs = [cc_user("go"), cc_use("a", "Bash", {"command": cmd}), cc_result("a", "")]
    s = _cc(tmp_path, objs)
    got = {(e.kind, e.path) for e in effects(s.steps[0])}
    assert got == expect


def test_apply_patch_effects_from_codex(tmp_path):
    s = Session.load(write_lines(tmp_path / "r.jsonl", codex_session()))
    got = {(e.kind, e.path) for e in effects(s.steps[1])}
    assert got == {("write", "src/a.py"), ("write", "src/b.py"), ("delete", "old.py")}
    assert {("write", "files.txt")} == {(e.kind, e.path) for e in effects(s.steps[0])}


def test_windows_paths_normalised(tmp_path):
    objs = [cc_user("go"), cc_use("a", "Write", {"file_path": "C:\\proj\\src\\a.py"}),
            cc_result("a", "ok")]
    s = _cc(tmp_path, objs)
    assert effects(s.steps[0])[0].path == "C:/proj/src/a.py"
    assert blame(s, "src/a.py")[0].step == 1


def test_blame_and_ledger(tmp_path):
    s = _cc(tmp_path)
    assert [e.step for e in blame(s, "main.py")] == [1, 2]
    assert [e.step for e in blame(s, "/work/app/out.*")] == [3]
    assert blame(s, "nope.py") == []
    assert set(file_ledger(s)) == {"/work/app/main.py", "/work/app/out.txt"}


def test_explain_sources_and_invented_value(tmp_path):
    objs = [
        cc_user("Fix the bug in /work/app/main.py"),
        cc_use("a", "Bash", {"command": "ls"}),
        cc_result("a", "configs/secret_settings.yaml\nREADME.md"),
        cc_use("b", "Read", {"file_path": "configs/secret_settings.yaml"}),
        cc_result("b", "x"),
        cc_use("c", "Read", {"file_path": "/work/app/main.py"}),
        cc_result("c", "y"),
        cc_use("d", "Read", {"file_path": "/etc/invented/path.cfg"}),
        cc_result("d", "z"),
    ]
    s = _cc(tmp_path, objs)
    by_val = {p.value: p for p in explain(s, 2).provenance}
    assert by_val["configs/secret_settings.yaml"].origin == "step 1 output"
    assert {p.value: p.origin for p in explain(s, 3).provenance}["/work/app/main.py"] == "prompt"
    ex = explain(s, 4)
    assert [p.value for p in ex.unsourced] == ["/etc/invented/path.cfg"]
    assert ex.prompt.startswith("Fix the bug")
    assert [n for n, _, _ in ex.turn_steps] == [1, 2, 3]


def test_explain_does_not_use_the_future_as_a_source(tmp_path):
    objs = [cc_user("go"),
            cc_use("a", "Read", {"file_path": "/late/file.txt"}), cc_result("a", "x"),
            cc_use("b", "Bash", {"command": "echo /late/file.txt"}), cc_result("b", "x")]
    s = _cc(tmp_path, objs)
    assert explain(s, 1).provenance[0].origin == "nowhere"
    assert explain(s, 2).provenance[0].origin == "step 1 args"


def test_explain_bad_step_and_weird_args(tmp_path):
    s = _cc(tmp_path)
    with pytest.raises(IndexError):
        explain(s, 99)
    objs = [cc_user("go"), cc_use("a", "Weird", {"x": [1, {"y": None}], "z": "q" * 9000}),
            cc_result("a", "")]
    assert explain(_cc(tmp_path, objs), 1) is not None


def test_breakpoint_specs(tmp_path):
    s = _cc(tmp_path)
    assert Breakpoint.parse("fail").matches(s.steps[2])
    assert not Breakpoint.parse("fail").matches(s.steps[0])
    assert Breakpoint.parse("bash").matches(s.steps[2])  # case-insensitive
    assert Breakpoint.parse("file:main.py").matches(s.steps[1])
    assert Breakpoint.parse("~pytest").matches(s.steps[2])
    assert Breakpoint.parse("slow:3000").matches(s.steps[2])
    assert not Breakpoint.parse("slow:3000").matches(s.steps[0])
    for bad in ("", "slow:abc", "~(unclosed", "~" + "a" * 600):
        with pytest.raises(ValueError):
            Breakpoint.parse(bad)


def test_run_to_breakpoint_forward_and_reverse(tmp_path):
    s = _cc(tmp_path)
    bps = [Breakpoint.parse("Edit"), Breakpoint.parse("fail")]
    assert run_to_breakpoint(s, 0, bps)[0] == 2
    assert run_to_breakpoint(s, 2, bps)[0] == 3
    assert run_to_breakpoint(s, 3, bps) == (None, None)
    assert run_to_breakpoint(s, 3, bps, reverse=True)[0] == 2
    assert run_to_breakpoint(s, 2, bps, reverse=True) == (None, None)


def test_repl_break_continue_why_files(tmp_path, capsys):
    s = _cc(tmp_path)
    repl = Repl(s, color=False)
    repl.run("break fail; c; rc; info break; tb Edit; c; why; files; blame main.py; delete 1; c")
    out = capsys.readouterr().out
    assert "hit breakpoint 1 (fail)" in out
    assert "why step 3" in out or "why step 2" in out
    assert "/work/app/main.py" in out
    assert "breakpoint 2: Edit" in out
    assert "deleted." in out and "no breakpoints set" in out  # tb consumed, 1 deleted


def test_cli_why_files_blame(tmp_path, capsys):
    p = write_lines(tmp_path / "c.jsonl", cc_session())
    assert main(["why", p, "3", "--json"]) == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["tool"] == "Bash" and doc["effects"][0]["path"] == "/work/app/out.txt"
    assert main(["why", p, "99"]) == 2
    assert main(["files", p]) == 0
    assert "/work/app/main.py  r1 w2" in capsys.readouterr().out
    assert main(["blame", p, "out.txt"]) == 0
    assert "step    3" in capsys.readouterr().out


def test_terminal_escapes_in_analysis_output_are_neutralised(tmp_path, capsys):
    evil = "\x1b[2Jevil\u202e.py"
    objs = [cc_user("go"), cc_use("a", "Write", {"file_path": evil}), cc_result("a", "ok")]
    p = write_lines(tmp_path / "c.jsonl", objs)
    for argv in (["files", p], ["blame", p, "evil*"], ["why", p, "1"]):
        main(argv)
        out = capsys.readouterr().out
        assert "\x1b" not in out and "\u202e" not in out
