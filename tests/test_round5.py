"""Round 5: author pin, upgrade path, SARIF/OTLP/digest, privacy flags,
property-style tests (seeded), golden files for every output format."""

import json
import os
import random
import re
import shutil
import subprocess
import sys

import pytest

HERE = os.path.dirname(__file__)
ROOT = os.path.join(HERE, "..")
SRC = os.path.join(ROOT, "src")
sys.path.insert(0, SRC)
sys.path.insert(0, HERE)

from logs import cc_result, cc_use, cc_user, fake_key, write_lines  # noqa: E402

import redbg  # noqa: E402
from redbg import Session, __version__  # noqa: E402
from redbg._meta import AUTHOR  # noqa: E402
from redbg.cli import main  # noqa: E402
from redbg.redact import (  # noqa: E402
    DEFAULT_VALUE_RES,
    HOME_PATH_RES,
    PII_VALUE_RES,
    _redact_string,
    literal_term_res,
    redact_event,
)

GOLDEN = os.path.join(HERE, "golden")
UPDATE = bool(os.environ.get("REDBG_UPDATE_GOLDEN"))


# -- author line -------------------------------------------------------------


def test_author_string_is_pinned_everywhere():
    assert AUTHOR == "Calas Automations Inc."
    assert redbg.__author__ == AUTHOR
    text = open(os.path.join(ROOT, "pyproject.toml"), encoding="utf-8").read()
    assert f'authors = [{{ name = "{AUTHOR}" }}]' in text
    assert f'maintainers = [{{ name = "{AUTHOR}" }}]' in text
    lic = open(os.path.join(ROOT, "LICENSE"), encoding="utf-8").read()
    assert f"Copyright (c) 2026 {AUTHOR}" in lic


def test_no_stale_owner_label_in_tracked_text():
    """'Calas Automations' must always be followed by ' Inc.' (the web address
    calasautomations.com is a different, lower-case spelling)."""
    stale = re.compile(r"Calas Automations(?! Inc\.)")
    skip_dirs = {".git", ".venv", "build", ".mypy_cache", "__pycache__", "redbg.egg-info"}
    for base, dirs, files in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in skip_dirs and not d.endswith(".egg-info")]
        for name in files:
            if not name.endswith((".py", ".md", ".toml", ".yml", ".in", ".txt", ".jsonl")):
                continue
            path = os.path.join(base, name)
            if os.path.abspath(path) == os.path.abspath(__file__):
                continue
            body = open(path, encoding="utf-8", errors="replace").read()
            assert not stale.search(body), f"stale author label in {path}"
            assert "Dan Calas" not in body, f"personal name in {path}"


def test_help_names_the_publisher(capsys):
    with pytest.raises(SystemExit):
        main(["--help"])
    assert f"redbg {__version__} - {AUTHOR}" in capsys.readouterr().out


# -- upgrade path from the version on the registry (0.1.1) ------------------


OLD = os.path.join(HERE, "fixtures", "redbg_0_1_1_session.jsonl")


def test_trace_recorded_by_0_1_1_still_works_everywhere(tmp_path, capsys):
    s = Session.load(OLD)
    assert [x.tool for x in s.steps] == ["read_file", "read_file", "flaky", "write_file"]
    assert [x.ok for x in s.steps] == [True, True, False, True]
    assert main(["info", OLD, "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["steps"] == 4
    assert main(["diff", OLD, OLD]) == 0
    assert main(["audit", OLD]) == 0
    assert main(["scan", OLD]) == 0
    assert main(["why", OLD, "3"]) == 0
    out = tmp_path / "r.jsonl"
    assert main(["redact", OLD, "-o", str(out)]) == 0
    assert main(["check", OLD, "--baseline", OLD]) == 0
    assert main(["check", OLD, "--max-failures", "0"]) == 1
    assert main(["otel", OLD, "-o", str(tmp_path / "o.json")]) == 0
    assert main(["digest", OLD]) == 0


def test_old_trace_schema_version_is_still_current():
    first = json.loads(open(OLD, encoding="utf-8").readline())
    assert first["v"] == redbg.SCHEMA_VERSION


# -- SARIF -------------------------------------------------------------------


@pytest.fixture()
def demo(tmp_path, monkeypatch):
    main(["demo", str(tmp_path)])
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_check_sarif_is_valid_shape(demo, capsys):
    rc = main(["check", "sample-b.jsonl", "--baseline", "sample-a.jsonl", "--sarif", "r.sarif"])
    assert rc == 1
    doc = json.loads((demo / "r.sarif").read_text(encoding="utf-8"))
    assert doc["version"] == "2.1.0"
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "redbg" and driver["organization"] == AUTHOR
    assert driver["version"] == __version__
    res = doc["runs"][0]["results"]
    assert res and all(r["level"] == "error" for r in res)
    rule_ids = {r["id"] for r in driver["rules"]}
    assert {r["ruleId"] for r in res} <= rule_ids
    uri = res[0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "sample-b.jsonl"


def test_check_sarif_passing_run_has_no_results(demo, capsys):
    assert main(["check", "sample-a.jsonl", "--sarif", "ok.sarif"]) == 0
    doc = json.loads((demo / "ok.sarif").read_text(encoding="utf-8"))
    assert doc["runs"][0]["results"] == []


def test_sarif_escapes_hostile_text_and_paths(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    name = "we ird\u202e.jsonl"
    write_lines(name, [cc_user("hi"), cc_use("t1", "Bash\x1b[2J\u202e", {"command": "ls"}),
                       cc_result("t1", "ok")])
    assert main(["check", name, "--forbid-tool", "bash*", "--sarif", "o.sarif"]) == 1
    text = (tmp_path / "o.sarif").read_text(encoding="utf-8")
    doc = json.loads(text)
    msg = doc["runs"][0]["results"][0]["message"]["text"]
    assert "\x1b" not in msg and "\u202e" not in msg
    assert "%20" in doc["runs"][0]["artifacts"][0]["location"]["uri"]


def test_audit_sarif_levels(demo):
    assert main(["audit", "sample-b.jsonl", "--sarif", "a.sarif"]) == 0
    doc = json.loads((demo / "a.sarif").read_text(encoding="utf-8"))
    levels = {r["level"] for r in doc["runs"][0]["results"]}
    assert levels <= {"error", "warning", "note"}


def test_sarif_unwritable_is_exit_2_not_traceback(demo, capsys):
    rc = main(["check", "sample-a.jsonl", "--sarif", "no/such/dir/x.sarif"])
    assert rc == 2
    err = capsys.readouterr().err
    assert "--sarif report not written" in err and "Traceback" not in err


def test_reports_never_overwrite_their_input(demo, capsys):
    before = (demo / "sample-a.jsonl").read_bytes()
    assert main(["check", "sample-a.jsonl", "--sarif", "sample-a.jsonl"]) == 2
    assert main(["audit", "sample-a.jsonl", "--sarif", "./sample-a.jsonl"]) == 2
    assert main(["otel", "sample-a.jsonl", "-o", "sample-a.jsonl"]) == 2
    assert main(["check", "sample-b.jsonl", "--baseline", "sample-a.jsonl",
                 "--sarif", "sample-a.jsonl"]) == 2
    assert (demo / "sample-a.jsonl").read_bytes() == before
    assert "refusing to overwrite" in capsys.readouterr().err


# -- OTLP --------------------------------------------------------------------


def test_otel_is_deterministic_and_has_no_args_by_default(demo, capsys):
    assert main(["otel", "sample-a.jsonl"]) == 0
    first = capsys.readouterr().out
    assert main(["otel", "sample-a.jsonl"]) == 0
    assert capsys.readouterr().out == first
    doc = json.loads(first)
    spans = doc["resourceSpans"][0]["scopeSpans"][0]["spans"]
    root, steps = spans[0], spans[1:]
    assert len(steps) == len(Session.load("sample-a.jsonl").steps)
    assert all(s["parentSpanId"] == root["spanId"] for s in steps)
    assert all(s["traceId"] == root["traceId"] and len(s["spanId"]) == 16 for s in steps)
    assert all(int(s["endTimeUnixNano"]) >= int(s["startTimeUnixNano"]) for s in spans)
    assert "redbg.args" not in first
    res_attrs = {a["key"]: a["value"]["stringValue"]
                 for a in doc["resourceSpans"][0]["resource"]["attributes"]}
    assert res_attrs["redbg.publisher"] == AUTHOR


def test_otel_with_args_redacts_first(tmp_path, capsys):
    key = fake_key()
    p = write_lines(tmp_path / "t.jsonl", [
        cc_user("go"), cc_use("t1", "Bash", {"command": f"echo {key}"}), cc_result("t1", "ok")])
    assert main(["otel", p, "--with-args"]) == 0
    out = capsys.readouterr().out
    assert "redbg.args" in out and key not in out and "REDACTED" in out


def test_otel_failed_step_has_error_status(demo, capsys):
    main(["otel", "sample-b.jsonl"])
    doc = json.loads(capsys.readouterr().out)
    codes = [s["status"]["code"] for s in doc["resourceSpans"][0]["scopeSpans"][0]["spans"][1:]]
    assert 2 in codes and 1 in codes


# -- digest ------------------------------------------------------------------


def test_digest_matches_hashlib_and_expect(demo, capsys):
    import hashlib

    want = hashlib.sha256((demo / "sample-a.jsonl").read_bytes()).hexdigest()
    assert main(["digest", "sample-a.jsonl", "--json"]) == 0
    info = json.loads(capsys.readouterr().out)
    assert info["sha256"] == want and info["bytes"] == (demo / "sample-a.jsonl").stat().st_size
    assert main(["digest", "sample-a.jsonl", "--expect", want.upper()]) == 0
    assert main(["digest", "sample-a.jsonl", "--expect", "0" * 64]) == 1


def test_digest_flags_spliced_and_reordered_lines(demo, capsys):
    lines = (demo / "sample-a.jsonl").read_text(encoding="utf-8").splitlines()
    (demo / "spliced.jsonl").write_text("\n".join(lines + [lines[2]]) + "\n", encoding="utf-8")
    assert main(["digest", "spliced.jsonl", "--json", "--strict"]) == 1
    info = json.loads(capsys.readouterr().out)
    assert info["duplicate_event_ids"] == 1
    moved = [json.loads(x) for x in lines]
    moved[3]["ts"] = "2030-01-01T00:00:00Z"  # one line stamped far in the future
    (demo / "swapped.jsonl").write_text(
        "\n".join(json.dumps(x) for x in moved) + "\n", encoding="utf-8")
    main(["digest", "swapped.jsonl", "--json"])
    assert json.loads(capsys.readouterr().out)["timestamps_going_backwards"] >= 1
    assert main(["digest", "sample-a.jsonl", "--strict"]) == 0


def test_digest_still_fingerprints_a_damaged_file(tmp_path, capsys):
    import hashlib

    bad = tmp_path / "bad.jsonl"
    bad.write_bytes(b'{"v": 1, "type": "note"}\nthis is not json\n')
    assert main(["digest", str(bad), "--json"]) == 2
    cap = capsys.readouterr()
    info = json.loads(cap.out)
    assert info["sha256"] == hashlib.sha256(bad.read_bytes()).hexdigest()
    assert "error" in info and "bad.jsonl" in cap.err


def test_digest_missing_file_is_exit_2(tmp_path, capsys):
    assert main(["digest", str(tmp_path / "nope.jsonl")]) == 2
    assert "no such file" in capsys.readouterr().err


# -- privacy flags -----------------------------------------------------------


def _privacy_trace(tmp_path):
    return write_lines(tmp_path / "p.jsonl", [
        cc_user("mail bob@example.org about /home/alice/proj"),
        cc_use("t1", "Bash", {"command": "cat C:\\Users\\Carl\\x /Users/dee/y; ping 10.1.2.3"},
               cwd="/home/alice/proj"),
        cc_result("t1", "Acme Corp host 192.168.1.20 version 1.2.3.4.5"),
    ])


def test_paths_pii_and_also_redact_and_scan_comes_back_clean(tmp_path, capsys):
    src = _privacy_trace(tmp_path)
    dst = str(tmp_path / "out.jsonl")
    flags = ["--pii", "--paths", "--also", "acme corp"]
    assert main(["redact", src, "-o", dst, *flags]) == 0
    body = open(dst, encoding="utf-8").read()
    for leak in ("alice", "Carl", "/Users/dee", "10.1.2.3", "192.168.1.20", "bob@", "Acme"):
        assert leak not in body, leak
    assert "/home/[REDACTED]/proj" in body            # the rest of the path survives
    assert "1.2.3.4.5" in body                        # not an IPv4: left alone
    assert main(["scan", dst, *flags]) == 0
    assert main(["scan", src, *flags]) == 1


def test_redact_keeps_the_input_format_for_claude_code_and_codex(tmp_path):
    from logs import codex_session

    from redbg.formats import sniff

    cc = _privacy_trace(tmp_path)
    cx = write_lines(tmp_path / "cx.jsonl", codex_session() + [
        {"timestamp": "2026-01-01T00:00:08.000Z", "type": "response_item",
         "payload": {"type": "message", "role": "user",
                     "content": [{"type": "input_text", "text": "see /home/alice/x"}]}}])
    for src in (cc, cx):
        dst = str(tmp_path / ("out_" + os.path.basename(src)))
        assert main(["redact", src, "-o", dst, "--paths"]) == 0
        assert sniff(dst) == sniff(src)
        assert "alice" not in open(dst, encoding="utf-8").read().replace("user alice", "")


def test_default_redact_leaves_personal_data_alone(tmp_path):
    src = _privacy_trace(tmp_path)
    dst = str(tmp_path / "out.jsonl")
    assert main(["redact", src, "-o", dst]) == 0
    body = open(dst, encoding="utf-8").read()
    assert "alice" in body and "10.1.2.3" in body     # opt-in only, as documented


@pytest.mark.parametrize("term", ["", " ", "x", "red", "REDACTED", "[REDACTED]"])
def test_also_refuses_dangerous_terms(term):
    with pytest.raises(ValueError):
        literal_term_res([term])


def test_also_bad_term_is_exit_2(tmp_path, capsys):
    src = _privacy_trace(tmp_path)
    assert main(["redact", src, "-o", str(tmp_path / "o.jsonl"), "--also", "red"]) == 2
    assert "redaction marker" in capsys.readouterr().err


def test_also_term_with_regex_characters_is_literal():
    res = literal_term_res(["a.b(c"])
    assert _redact_string("xa.b(cx axb(c", res, [0]) == "x[REDACTED]x axb(c"


# -- property-style tests (seeded; no extra dependency) ---------------------


def _keys():
    return [
        "sk-" + "ant-" + "api03-" + "Zq9" * 12,
        "gh" + "p_" + "A1b2" * 6,
        "AK" + "IA" + "ABCDEFGHIJKLMNOP",
        "xo" + "xb-" + "1234567890-abcdefghij",
    ]


_ALPHABET = "abc XYZ-_./:=\\\"'\n\t\u00e9\u202e{}[]0123456789@"
ALL_RES = DEFAULT_VALUE_RES + PII_VALUE_RES + HOME_PATH_RES


def _noise(rng, n=40):
    return "".join(rng.choice(_ALPHABET) for _ in range(rng.randint(0, n)))


def test_property_embedded_secret_never_survives_and_redaction_is_idempotent():
    rng = random.Random(20261108)
    keys = _keys()
    for _ in range(1500):
        key = rng.choice(keys)
        text = _noise(rng) + key + _noise(rng) + " /home/zed/x 10.0.0.1 a@b.co"
        once = _redact_string(text, ALL_RES, [0])
        assert key not in once, text
        again = [0]
        assert _redact_string(once, ALL_RES, again) == once and again[0] == 0, text


def test_property_event_redaction_is_idempotent_on_nested_data():
    rng = random.Random(7)
    keys = _keys()

    def tree(depth):
        pick = rng.random()
        if depth > 3 or pick < 0.4:
            return _noise(rng) + rng.choice(keys) + _noise(rng)
        if pick < 0.7:
            return [tree(depth + 1) for _ in range(rng.randint(0, 3))]
        names = ["a", "token", "path", "x_key", "n", "api_key", "nested"]
        return {rng.choice(names): tree(depth + 1) for _ in range(rng.randint(0, 3))}

    for _ in range(300):
        ev = {"type": "note", "v": 1, "id": "i", "ts": "t", "mono": 1.0, "text": tree(0)}
        once, _n = redact_event(ev, value_res=ALL_RES)
        twice, n2 = redact_event(once, value_res=ALL_RES)
        assert once == twice and n2 == 0
        assert not any(k in json.dumps(once) for k in keys)


def test_property_hostile_ids_never_crash_loading():
    """call ids that are lists/dicts used to raise TypeError while indexing."""
    rng = random.Random(3)
    odd = [[], {}, [1, [2]], {"a": [1]}, None, 0, "", 1.5, True]
    for _ in range(200):
        events = []
        for i in range(rng.randint(1, 6)):
            events.append({"v": 1, "id": rng.choice(odd), "ts": "2026-01-01T00:00:00Z",
                           "mono": float(i), "type": rng.choice(["tool_call", "tool_result"]),
                           "step": i, "tool": rng.choice(["t", 3, None, ["x"]]),
                           "call_id": rng.choice(odd), "ok": rng.choice(odd),
                           "args": rng.choice(odd), "output": rng.choice(odd),
                           "error": rng.choice(odd)})
        import tempfile

        with tempfile.TemporaryDirectory() as d:
            p = write_lines(os.path.join(d, "t.jsonl"), events)
            s = Session.load(p, skip_bad=True)
            redbg.render_diff(s, s, use_color=False)
            redbg.file_ledger(s)
            from redbg.htmlexport import render_html

            render_html(s)
            for n in range(1, len(s.steps) + 1):
                redbg.explain(s, n)
            if s.steps:
                try:
                    redbg.fork_session(s, redbg.ForkSpec(at_step=1))
                except ValueError:
                    pass


def test_unhashable_call_id_pairs_up_by_value():
    ev = [
        {"v": 1, "id": [1, 2], "ts": "2026-01-01T00:00:00Z", "mono": 0.0,
         "type": "tool_call", "step": 1, "tool": "t", "args": {}},
        {"v": 1, "id": "r", "ts": "2026-01-01T00:00:01Z", "mono": 1.0,
         "type": "tool_result", "step": 1, "call_id": [1, 2], "tool": "t", "ok": True,
         "output": "fine"},
    ]
    s = Session(path="mem", events=ev)
    s._index()
    assert len(s.steps) == 1 and s.steps[0].ok is True


def test_odd_output_and_args_types_are_text_and_dict():
    ev = [
        {"v": 1, "id": "c", "ts": "2026-01-01T00:00:00Z", "mono": 0.0, "type": "tool_call",
         "step": 1, "tool": "t", "args": [1, 2]},
        {"v": 1, "id": "r", "ts": "2026-01-01T00:00:01Z", "mono": 1.0, "type": "tool_result",
         "step": 1, "call_id": "c", "tool": "t", "ok": False, "output": {"a": 1}, "error": 3.5},
    ]
    s = Session(path="mem", events=ev)
    s._index()
    st = s.steps[0]
    assert st.args == {"_args": [1, 2]}
    assert st.output == '{"a": 1}' and st.error == "3.5"


# -- mutation-style sanity (cheap, in-process) -------------------------------


def test_mutation_sanity_key_conditions_matter():
    """If these conditions were flipped the assertions would fail: guards
    against tests that pass whatever the code does. (The full run over the
    source lives in bench/mutation_sanity.py.)"""
    keyed = redbg.redact.DEFAULT_KEY_RE
    assert keyed.search("api_key") and not keyed.search("author")
    from redbg.check import CheckRules, run_check

    s = Session.load(OLD)
    assert run_check(s, CheckRules(max_steps=1)).passed is False
    assert run_check(s, CheckRules(max_steps=99, max_failures=5)).passed is True


# -- golden files for every output format ------------------------------------

GOLDEN_CASES = {
    "check_json": ["check", "sample-b.jsonl", "--baseline", "sample-a.jsonl", "--json"],
    "check_github": ["check", "sample-b.jsonl", "--baseline", "sample-a.jsonl", "--github"],
    "check_text": ["check", "sample-b.jsonl", "--baseline", "sample-a.jsonl", "--no-color"],
    "audit_json": ["audit", "sample-b.jsonl", "--json"],
    "audit_text": ["audit", "sample-b.jsonl", "--no-color"],
    "info_json": ["info", "sample-b.jsonl", "--json"],
    "diff_text": ["diff", "sample-a.jsonl", "sample-b.jsonl", "--no-color"],
    "diff_json": ["diff", "sample-a.jsonl", "sample-b.jsonl", "--json"],
    "otel_json": ["otel", "sample-b.jsonl"],
    "otel_args_json": ["otel", "sample-b.jsonl", "--with-args"],
    "digest_json": ["digest", "sample-b.jsonl", "--json"],
    "files_json": ["files", "sample-b.jsonl", "--json"],
    "why_json": ["why", "sample-b.jsonl", "3", "--json"],
}
FILE_CASES = {
    "check_junit": (["check", "sample-b.jsonl", "--baseline", "sample-a.jsonl", "--junit", "o.xml"], "o.xml"),
    "check_sarif": (["check", "sample-b.jsonl", "--baseline", "sample-a.jsonl", "--sarif", "o.sarif"], "o.sarif"),
    "audit_sarif": (["audit", "sample-b.jsonl", "--sarif", "o.sarif"], "o.sarif"),
    "replay_md": (["replay", "sample-b.jsonl", "--export-md", "o.md"], "o.md"),
    "replay_html": (["replay", "sample-b.jsonl", "--export-html", "o.html"], "o.html"),
}


def _check_golden(name, text):
    path = os.path.join(GOLDEN, name + ".txt")
    text = text.replace("\r\n", "\n")
    if UPDATE:
        os.makedirs(GOLDEN, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return
    assert os.path.exists(path), f"missing golden file {path} (run with REDBG_UPDATE_GOLDEN=1)"
    want = open(path, encoding="utf-8", newline="").read().replace("\r\n", "\n")
    assert text == want, f"output of {name} changed; if intended, REDBG_UPDATE_GOLDEN=1 pytest"


@pytest.mark.parametrize("name", sorted(GOLDEN_CASES))
def test_golden_stdout(name, demo, capsys, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    main(GOLDEN_CASES[name])
    captured = capsys.readouterr()
    assert "Traceback" not in captured.err
    _check_golden(name, captured.out)


@pytest.mark.parametrize("name", sorted(FILE_CASES))
def test_golden_files(name, demo, capsys, monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    argv, produced = FILE_CASES[name]
    main(argv)
    capsys.readouterr()
    _check_golden(name, (demo / produced).read_text(encoding="utf-8"))


def test_golden_directory_has_no_orphans():
    want = {n + ".txt" for n in list(GOLDEN_CASES) + list(FILE_CASES)}
    have = {n for n in os.listdir(GOLDEN) if n.endswith(".txt")}
    assert have == want


# -- subprocess smoke (real entry point, odd locale) --------------------------


def test_new_commands_survive_ascii_console(demo):
    env = dict(os.environ, PYTHONPATH=SRC, PYTHONIOENCODING="ascii")
    for argv in (["otel", "sample-b.jsonl"], ["digest", "sample-b.jsonl"],
                 ["audit", "sample-b.jsonl", "--sarif", "z.sarif"]):
        r = subprocess.run([sys.executable, "-m", "redbg", *argv], capture_output=True,
                           env=env, cwd=str(demo))
        assert r.returncode == 0, r.stderr
        assert b"Traceback" not in r.stderr


def test_checkout_contains_no_copy_of_the_example_in_golden_dir_names():
    assert shutil.which("python3") or sys.executable
