"""Round 4: what a stranger who ran `pip install redbg` actually gets."""

import json
import os
import re
import subprocess
import sys

import pytest

SRC = os.path.join(os.path.dirname(__file__), "..", "src")
sys.path.insert(0, SRC)

from redbg import __version__, cli  # noqa: E402
from redbg.cli import main  # noqa: E402

ROOT = os.path.join(os.path.dirname(__file__), "..")


def _run(args, env_extra=None):
    env = dict(os.environ, PYTHONPATH=SRC)
    env.update(env_extra or {})
    return subprocess.run(
        [sys.executable, "-m", "redbg", *args],
        capture_output=True, env=env,
    )


# -- demo -------------------------------------------------------------------


def test_demo_writes_samples_identical_to_examples(tmp_path, capsys):
    dest = tmp_path / "my demo"  # a space in the path on purpose
    assert main(["demo", str(dest)]) == 0
    out = capsys.readouterr().out
    assert "redbg diff" in out and '"' in out  # paths with spaces are quoted
    for name in ("sample-a.jsonl", "sample-b.jsonl"):
        shipped = (dest / name).read_bytes()
        assert shipped == open(os.path.join(ROOT, "examples", name), "rb").read()


def test_demo_samples_work_end_to_end(tmp_path, capsys):
    main(["demo", str(tmp_path)])
    capsys.readouterr()
    a, b = str(tmp_path / "sample-a.jsonl"), str(tmp_path / "sample-b.jsonl")
    assert main(["check", b, "--baseline", a]) == 1
    assert main(["check", a]) == 0


def test_demo_refuses_to_overwrite(tmp_path, capsys):
    assert main(["demo", str(tmp_path)]) == 0
    (tmp_path / "sample-a.jsonl").write_text("mine")
    capsys.readouterr()
    assert main(["demo", str(tmp_path)]) == 2
    assert "--force" in capsys.readouterr().err
    assert (tmp_path / "sample-a.jsonl").read_text() == "mine"
    assert main(["demo", str(tmp_path), "--force"]) == 0


def test_demo_into_a_file_is_a_plain_error(tmp_path, capsys):
    blocker = tmp_path / "f"
    blocker.write_text("x")
    assert main(["demo", str(blocker / "sub")]) == 2
    err = capsys.readouterr().err
    assert "Traceback" not in err and "redbg:" in err


# -- sessions ---------------------------------------------------------------


def test_sessions_lists_newest_first(tmp_path, capsys):
    old = tmp_path / "p1" / "old.jsonl"
    new = tmp_path / "p2" / "new.jsonl"
    for f in (old, new):
        f.parent.mkdir()
        f.write_text("{}\n")
    os.utime(old, (1_000_000, 1_000_000))
    (tmp_path / "p2" / "notes.txt").write_text("ignore me")
    assert main(["sessions", "--dir", str(tmp_path)]) == 0
    out = capsys.readouterr().out
    assert out.index("new.jsonl") < out.index("old.jsonl")
    assert "notes.txt" not in out


def test_sessions_json_and_limit(tmp_path, capsys):
    for i in range(4):
        (tmp_path / f"s{i}.jsonl").write_text("{}\n")
    assert main(["sessions", "--dir", str(tmp_path), "--json", "--limit", "2"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert len(rows) == 2 and {"path", "bytes", "modified"} <= set(rows[0])


def test_sessions_none_found_exits_2(tmp_path, capsys):
    assert main(["sessions", "--dir", str(tmp_path / "missing")]) == 2
    assert "no transcripts found" in capsys.readouterr().err


# -- entry points -----------------------------------------------------------


def test_python_dash_m_redbg_matches_the_command():
    proc = _run(["--version"])
    assert proc.returncode == 0
    assert proc.stdout.decode().strip() == f"redbg {__version__}"


def test_help_documents_exit_codes():
    proc = _run(["--help"])
    text = proc.stdout.decode()
    assert "exit codes" in text and "redbg demo" in text


# -- hostile consoles and files --------------------------------------------


@pytest.mark.parametrize("encoding", ["ascii", "cp1252"])
def test_unencodable_console_does_not_crash(encoding, tmp_path):
    main(["demo", str(tmp_path)])
    # The diff report prints check marks and arrows that neither code page has.
    proc = _run(
        ["diff", str(tmp_path / "sample-a.jsonl"), str(tmp_path / "sample-b.jsonl")],
        {"PYTHONIOENCODING": encoding, "PYTHONUTF8": "0"},
    )
    assert b"Traceback" not in proc.stderr
    assert proc.returncode == 0
    assert b"First divergence" in proc.stdout


def test_write_errors_are_plain_not_tracebacks(tmp_path, capsys):
    main(["demo", str(tmp_path)])
    a = str(tmp_path / "sample-a.jsonl")
    bad = str(tmp_path / "sample-a.jsonl" / "out")  # parent is a file
    for argv in (
        ["replay", a, "--export-md", bad],
        ["replay", a, "--export-html", bad],
        ["check", a, "--junit", bad],
        ["fork", a, "--at", "1", "--save", bad],
        ["redact", a, "-o", bad],
    ):
        capsys.readouterr()
        assert main(argv) == 2, argv
        err = capsys.readouterr().err
        assert "Traceback" not in err and err.startswith("redbg:"), argv
        assert "[Errno" not in err, argv


def test_missing_file_message_is_plain(capsys):
    assert main(["info", "no-such-trace.jsonl"]) == 2
    err = capsys.readouterr().err
    assert "cannot open 'no-such-trace.jsonl'" in err and "[Errno" not in err


def test_folder_as_trace_is_plain(tmp_path, capsys):
    assert main(["info", str(tmp_path)]) == 2
    assert "is a folder" in capsys.readouterr().err


def test_tools_file_that_raises_is_exit_2(tmp_path, capsys):
    main(["demo", str(tmp_path)])
    tools = tmp_path / "tools.py"
    tools.write_text("raise RuntimeError('boom')\n")
    capsys.readouterr()
    code = main(["fork", str(tmp_path / "sample-a.jsonl"), "--at", "1", "--tools", str(tools)])
    err = capsys.readouterr().err
    assert code == 2 and "boom" in err and "Traceback" not in err


def test_tools_file_calling_exit_is_exit_2(tmp_path, capsys):
    main(["demo", str(tmp_path)])
    tools = tmp_path / "tools.py"
    tools.write_text("import sys\nsys.exit(0)\n")  # must not pass as success
    capsys.readouterr()
    code = main(["fork", str(tmp_path / "sample-a.jsonl"), "--at", "1", "--tools", str(tools)])
    assert code == 2


def test_unexpected_crash_is_exit_2_not_1(monkeypatch, tmp_path, capsys):
    main(["demo", str(tmp_path)])
    capsys.readouterr()

    def boom(args):
        raise RuntimeError("kaboom")

    p = str(tmp_path / "sample-a.jsonl")
    monkeypatch.setattr(cli, "cmd_info", boom)
    assert main(["info", p]) == 2
    err = capsys.readouterr().err
    assert "kaboom" in err and "REDBG_DEBUG" in err and "Traceback" not in err
    monkeypatch.setenv("REDBG_DEBUG", "1")
    with pytest.raises(RuntimeError):
        main(["info", p])


def test_ctrl_c_is_130(monkeypatch, tmp_path, capsys):
    main(["demo", str(tmp_path)])

    def stop(args):
        raise KeyboardInterrupt

    monkeypatch.setattr(cli, "cmd_info", stop)
    assert main(["info", str(tmp_path / "sample-a.jsonl")]) == 130


# -- atomic writes, line endings -------------------------------------------


def test_redact_failure_leaves_no_partial_output(tmp_path, capsys):
    src = tmp_path / "in.jsonl"
    src.write_text('{"type":"note","text":"ok"}\n{broken\n')
    dst = tmp_path / "out.jsonl"
    assert main(["redact", str(src), "-o", str(dst)]) == 2
    assert not dst.exists() and not (tmp_path / "out.jsonl.part").exists()


def test_redact_keeps_an_existing_good_output_on_failure(tmp_path):
    src = tmp_path / "in.jsonl"
    src.write_text("{broken\n")
    dst = tmp_path / "out.jsonl"
    dst.write_text("previous good output\n")
    assert main(["redact", str(src), "-o", str(dst)]) == 2
    assert dst.read_text() == "previous good output\n"


@pytest.mark.skipif(not os.path.exists(os.devnull), reason="needs a null device")
def test_redact_can_write_to_the_null_device(tmp_path):
    main(["demo", str(tmp_path)])
    assert main(["redact", str(tmp_path / "sample-a.jsonl"), "-o", os.devnull]) == 0
    assert os.path.exists(os.devnull)  # was not replaced by a regular file
    assert not os.path.isfile(os.devnull)


def test_written_files_use_unix_newlines(tmp_path):
    from redbg import Recorder

    path = tmp_path / "t.jsonl"
    with Recorder(str(path)) as rec:
        c = rec.tool_call("x", {"a": 1})
        rec.tool_result(c, ok=True, output="line1\nline2")
    assert b"\r" not in path.read_bytes()
    md = tmp_path / "r.md"
    assert main(["replay", str(path), "--export-md", str(md)]) == 0
    assert b"\r" not in md.read_bytes()


# -- release hygiene --------------------------------------------------------


def test_versions_agree_everywhere():
    text = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert re.search(rf'^version = "{re.escape(__version__)}"$', text, re.M)
    log = open(os.path.join(ROOT, "CHANGELOG.md"), encoding="utf-8").read()
    first = re.search(r"^## (\d+\.\d+\.\d+)", log, re.M).group(1)
    assert first == __version__


def test_package_ships_license_and_type_marker():
    import importlib.resources as resources

    assert (resources.files("redbg") / "py.typed").is_file()
    assert (resources.files("redbg") / "_samples" / "sample-a.jsonl").is_file()
    assert os.path.exists(os.path.join(ROOT, "LICENSE"))
    text = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert 'name = "Calas Automations Inc."' in text
    assert "github.com/calasdan-sketch/redbg" in text


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_redact_writes_through_a_symlinked_output(tmp_path):
    main(["demo", str(tmp_path)])
    real = tmp_path / "real.jsonl"
    real.write_text("old")
    link = tmp_path / "link.jsonl"
    os.symlink(real, link)
    assert main(["redact", str(tmp_path / "sample-a.jsonl"), "-o", str(link)]) == 0
    assert os.path.islink(link)  # the link survives
    assert real.read_text().startswith("{")


def test_demo_force_over_a_folder_is_plain(tmp_path, capsys):
    (tmp_path / "sample-a.jsonl").mkdir()
    assert main(["demo", str(tmp_path), "--force"]) == 2
    assert "Traceback" not in capsys.readouterr().err
