import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from redbg import CheckRules, Recorder, Session, run_check  # noqa: E402
from redbg.cli import main  # noqa: E402
from redbg.diff import diff_to_dict, find_repeats, normalize_args  # noqa: E402


def _record(path, calls, crash=False):
    """calls: list of (tool, args, ok)."""

    def body(rec):
        for tool, args, ok in calls:
            c = rec.tool_call(tool, args)
            if ok:
                rec.tool_result(c, ok=True, output=f"{tool} ok")
            else:
                rec.tool_result(c, ok=False, error="boom")

    if crash:
        with pytest.raises(RuntimeError), Recorder(path) as rec:
            body(rec)
            raise RuntimeError("agent crashed")
    else:
        with Recorder(path) as rec:
            body(rec)
    return path


# -- normalization ---------------------------------------------------------


def test_normalize_integral_floats_and_ignore_keys():
    assert normalize_args({"a": 1.0, "b": [2.0, 2.5], "c": True}) == {
        "a": 1,
        "b": [2, 2.5],
        "c": True,
    }
    assert normalize_args({"id": "x", "n": {"id": "y", "k": 1}}, {"id"}) == {
        "n": {"k": 1}
    }


def test_normalize_survives_deep_nesting():
    deep: dict = {}
    cur = deep
    for _ in range(1000):
        cur["x"] = {}
        cur = cur["x"]
    normalize_args(deep)  # must not raise RecursionError


def test_diff_treats_1_and_1_0_as_equal(tmp_path):
    a = Session.load(_record(str(tmp_path / "a.jsonl"), [("t", {"n": 1}, True)]))
    b = Session.load(_record(str(tmp_path / "b.jsonl"), [("t", {"n": 1.0}, True)]))
    assert diff_to_dict(a, b)["identical"] is True


def test_diff_ignore_keys(tmp_path):
    a = Session.load(
        _record(str(tmp_path / "a.jsonl"), [("t", {"q": "x", "req_id": "1"}, True)])
    )
    b = Session.load(
        _record(str(tmp_path / "b.jsonl"), [("t", {"q": "x", "req_id": "2"}, True)])
    )
    assert diff_to_dict(a, b)["identical"] is False
    assert diff_to_dict(a, b, ignore_keys=["req_id"])["identical"] is True


def test_diff_non_dict_args_do_not_crash(tmp_path):
    a = Session.load(_record(str(tmp_path / "a.jsonl"), [("t", [1, 2], True)]))
    b = Session.load(_record(str(tmp_path / "b.jsonl"), [("t", [1, 3], True)]))
    d = diff_to_dict(a, b)
    assert d["divergence"]["kind"] == "args_changed"


def test_diff_json_cli(trace_ok, trace_fail, capsys):
    assert main(["diff", trace_ok, trace_fail, "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    assert data["identical"] is False
    assert data["divergence"]["kind"] in ("args_changed", "status_changed")
    assert set(data["counts"]) >= {"same", "added", "removed"}
    assert all("kind" in row for row in data["rows"])


# -- loop detection --------------------------------------------------------


def test_find_repeats(tmp_path):
    calls = [("a", {}, True)] + [("poll", {"id": 1}, True)] * 4 + [("b", {}, True)]
    s = Session.load(_record(str(tmp_path / "s.jsonl"), calls))
    runs = find_repeats(s)
    assert len(runs) == 1
    assert (runs[0].tool, runs[0].first, runs[0].last, runs[0].count) == (
        "poll",
        2,
        5,
        4,
    )


def test_find_repeats_trailing_run_and_none(tmp_path):
    s = Session.load(_record(str(tmp_path / "s.jsonl"), [("x", {}, True)] * 3))
    assert [r.count for r in find_repeats(s)] == [3]
    s2 = Session.load(
        _record(str(tmp_path / "t.jsonl"), [("x", {"i": i}, True) for i in range(3)])
    )
    assert find_repeats(s2) == []


def test_info_mentions_possible_loop(tmp_path, capsys):
    path = _record(str(tmp_path / "s.jsonl"), [("poll", {}, True)] * 3)
    assert main(["info", path, "--no-color"]) == 0
    assert "possible loop" in capsys.readouterr().out


# -- run_check rules -------------------------------------------------------


def test_check_passes_clean_session(trace_ok):
    result = run_check(Session.load(trace_ok), CheckRules())
    assert result.passed
    assert result.checked == ["non_empty", "complete"]


def test_check_detects_crash(tmp_path):
    path = _record(str(tmp_path / "s.jsonl"), [("t", {}, True)], crash=True)
    result = run_check(Session.load(path), CheckRules())
    assert not result.passed
    assert "error" in result.violations[0].message


def test_check_detects_truncated_trace(tmp_path, trace_ok):
    lines = open(trace_ok).read().splitlines()
    path = tmp_path / "cut.jsonl"
    path.write_text("\n".join(lines[:-2]) + "\n")  # drop last result + end
    result = run_check(Session.load(str(path)), CheckRules())
    rules = [v.rule for v in result.violations]
    assert rules.count("complete") == 2  # no session_end + step without result
    relaxed = CheckRules(require_complete=False, max_steps=10)
    assert run_check(Session.load(str(path)), relaxed).passed


def test_check_budgets_and_tools(tmp_path):
    calls = [
        ("read", {}, True),
        ("delete_file", {"p": 1}, False),
        ("delete_dir", {}, False),
    ]
    s = Session.load(_record(str(tmp_path / "s.jsonl"), calls))
    result = run_check(
        s,
        CheckRules(
            max_steps=2,
            max_failures=1,
            forbid_tools=["delete_*"],
            require_tools=["write*"],
        ),
    )
    rules = sorted(v.rule for v in result.violations)
    assert rules == [
        "forbid_tools",
        "forbid_tools",
        "max_failures",
        "max_steps",
        "require_tools",
    ]


@pytest.mark.parametrize(
    "tool",
    [
        "Delete_File",
        "DELETE_dir",
        "delete\u200b_file",
        "\uff44elete_file",
        "delete\u202e_x",
    ],
)
def test_forbid_matches_normalized_names(tmp_path, tool):
    # Regression (panel #6): case, zero-width and full-width variants used to
    # slip past --forbid-tool 'delete_*'.
    s = Session.load(_record(str(tmp_path / "s.jsonl"), [(tool, {}, True)]))
    result = run_check(s, CheckRules(forbid_tools=["delete_*"]))
    assert [v.rule for v in result.violations] == ["forbid_tools"]


def test_require_tool_is_normalized_too(tmp_path):
    s = Session.load(_record(str(tmp_path / "s.jsonl"), [("Write_Report", {}, True)]))
    assert run_check(s, CheckRules(require_tools=["write_*"])).passed


def test_forbid_does_not_overmatch(tmp_path):
    s = Session.load(_record(str(tmp_path / "s.jsonl"), [("undelete", {}, True)]))
    assert run_check(s, CheckRules(forbid_tools=["delete_*"])).passed


def test_check_max_repeats(tmp_path):
    s = Session.load(_record(str(tmp_path / "s.jsonl"), [("poll", {}, True)] * 5))
    assert run_check(s, CheckRules(max_repeats=5)).passed
    result = run_check(s, CheckRules(max_repeats=4))
    assert [v.rule for v in result.violations] == ["max_repeats"]


def test_check_against_baseline(trace_ok, trace_fail):
    base, cand = Session.load(trace_ok), Session.load(trace_fail)
    result = run_check(cand, CheckRules(), baseline=base)
    assert not result.passed
    assert result.violations[0].rule == "divergence"
    assert run_check(base, CheckRules(), baseline=base).passed


def test_check_fail_on_subset(tmp_path):
    a = Session.load(_record(str(tmp_path / "a.jsonl"), [("t", {"x": 1}, True)]))
    b = Session.load(_record(str(tmp_path / "b.jsonl"), [("t", {"x": 2}, True)]))
    assert not run_check(b, CheckRules(), baseline=a).passed
    assert run_check(b, CheckRules(fail_on=("tool_changed",)), baseline=a).passed


def test_check_output_changed_opt_in(tmp_path):
    def rec(path, out):
        with Recorder(path) as r:
            c = r.tool_call("t", {})
            r.tool_result(c, ok=True, output=out)
        return Session.load(path)

    a = rec(str(tmp_path / "a.jsonl"), "one")
    b = rec(str(tmp_path / "b.jsonl"), "two")
    assert run_check(b, CheckRules(), baseline=a).passed  # outputs vary by default
    result = run_check(b, CheckRules(fail_on=("output_changed",)), baseline=a)
    assert [v.rule for v in result.violations] == ["output_changed"]


def test_rules_validation():
    with pytest.raises(ValueError, match="unknown fail_on"):
        CheckRules(fail_on=("nonsense",))
    with pytest.raises(ValueError, match="max_steps"):
        CheckRules(max_steps=-1)


# -- CLI --------------------------------------------------------------------


def test_cli_check_exit_codes(trace_ok, trace_fail, capsys):
    assert main(["check", trace_ok, "--no-color"]) == 0
    assert "check passed" in capsys.readouterr().out
    assert main(["check", trace_fail, "--baseline", trace_ok, "--no-color"]) == 1
    out = capsys.readouterr().out
    assert "check FAILED" in out and "[divergence]" in out
    assert main(["check", "/nope.jsonl"]) == 2
    assert main(["check", trace_ok, "--fail-on", "bogus"]) == 2


def test_cli_check_json_and_csv_options(tmp_path, capsys):
    path = _record(
        str(tmp_path / "s.jsonl"), [("rm", {}, True), ("poll", {}, True)] * 1
    )
    code = main(
        [
            "check",
            path,
            "--forbid-tool",
            "rm,shutdown",
            "--require-tool",
            "poll",
            "--max-repeats",
            "3",
            "--json",
        ]
    )
    data = json.loads(capsys.readouterr().out)
    assert code == 1
    assert data["passed"] is False
    assert [v["rule"] for v in data["violations"]] == ["forbid_tools"]


def test_cli_check_limit(tmp_path, capsys):
    path = _record(
        str(tmp_path / "s.jsonl"), [("rm", {"i": i}, True) for i in range(5)]
    )
    assert main(["check", path, "--forbid-tool", "rm", "--limit", "2"]) == 1
    out = capsys.readouterr().out
    assert out.count("[forbid_tools]") == 2
    assert "3 more" in out
