from __future__ import annotations

import re

from logs import cc_result, cc_use, cc_user, fake_key, write_lines

from redbg.cli import main


def _evil_log(tmp_path):
    payload = "</pre></details><script>alert(1)</script><img src=x onerror=alert(2)>"
    objs = [
        cc_user("go " + payload),
        cc_use("a", "Bash", {"command": payload + "\u202e\x1b[2J", "k": fake_key()}),
        cc_result("a", payload + " " + fake_key()),
    ]
    return write_lines(tmp_path / "c.jsonl", objs)


def test_html_is_inert_and_redacted_by_default(tmp_path, capsys):
    p = _evil_log(tmp_path)
    out = tmp_path / "r.html"
    assert main(["replay", p, "--export-html", str(out)]) == 0
    html = out.read_text(encoding="utf-8")
    assert "<script" not in html.lower().replace("&lt;script", "")
    assert "<img" not in html and "onerror=alert" not in html.replace("&lt;img src=x onerror=alert(2)&gt;", "")
    assert "\u202e" not in html and "\x1b" not in html
    assert fake_key() not in html
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert len(re.findall(r"<details", html)) == html.count("</details>")


def test_html_unredacted_only_on_explicit_flag(tmp_path, capsys):
    p = _evil_log(tmp_path)
    out = tmp_path / "r.html"
    assert main(["replay", p, "--export-html", str(out), "--no-redact-html"]) == 0
    assert fake_key() in out.read_text(encoding="utf-8")
    assert "NOT redacted" in capsys.readouterr().out


def test_replay_redact_flag_scrubs_terminal_output(tmp_path, capsys):
    p = _evil_log(tmp_path)
    assert main(["replay", p, "--show", "1", "--redact"]) == 0
    assert fake_key() not in capsys.readouterr().out
