"""Self-contained, share-safe HTML report of a session.

Safe by construction, not by sanitising afterwards:

* every piece of trace content goes through ``html.escape`` and the
  terminal/bidi escaper in ``_text.clean`` - nothing from a trace is ever
  emitted as markup;
* the page contains no ``<script>``, no external resource and no event
  handler, and carries a ``Content-Security-Policy`` meta that forbids
  all of them, so a bug here still cannot execute trace content;
* the caller redacts the session first (``Session.load(redact=True)``);
  this module only renders.
"""

from __future__ import annotations

import html
import json

from ._text import clean
from .analysis import effects

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; img-src 'none'; "
    "base-uri 'none'; form-action 'none'"
)
_CSS = """
body{font:14px/1.45 system-ui,sans-serif;margin:0 auto;max-width:980px;padding:16px;
background:#fff;color:#1b1f24}
@media(prefers-color-scheme:dark){body{background:#0f1318;color:#e6e9ee}
details{border-color:#2b3340}pre{background:#171c24}.fail{color:#ff7b72}.ok{color:#56d364}}
h1{font-size:20px}.meta{color:#6b7380}
details{border:1px solid #d0d7de;border-radius:6px;margin:6px 0;padding:6px 10px}
summary{cursor:pointer;font-weight:600}
pre{white-space:pre-wrap;word-break:break-word;background:#f6f8fa;padding:8px;
border-radius:4px;max-height:420px;overflow:auto}
.fail{color:#cf222e}.ok{color:#1a7f37}.tag{font-size:12px;color:#6b7380}
"""


def _e(text) -> str:
    return html.escape(clean(text), quote=True)


def _cut(text: str, limit: int) -> str:
    if len(text) > limit:
        return text[:limit] + f"\n...[{len(text) - limit} more chars]"
    return text


def render_html(session, max_chars: int = 8000, redactions: int | None = None) -> str:
    total = len(session.steps)
    failed = sum(1 for s in session.steps if s.ok is False)
    parts = [
        "<!doctype html><html lang=en><head><meta charset=utf-8>",
        f'<meta http-equiv="Content-Security-Policy" content="{CSP}">',
        '<meta name=viewport content="width=device-width,initial-scale=1">',
        f"<title>redbg session report</title><style>{_CSS}</style></head><body>",
        "<h1>redbg session report</h1>",
        f'<p class=meta>agent <b>{_e(session.agent)}</b> &middot; {total} steps '
        f"&middot; {failed} failed &middot; status {_e(session.status or 'unknown')}",
    ]
    if redactions is not None:
        parts.append(f" &middot; {redactions} value(s) redacted")
    parts.append("</p>")
    last_prompt = None
    for step in session.steps:
        if step.prompt_ctx is not last_prompt and step.prompt_ctx:
            last_prompt = step.prompt_ctx
            parts.append(
                "<details open><summary>prompt</summary><pre>"
                f"{_e(_cut(str(last_prompt.get('text', '')), 2000))}</pre></details>"
            )
        status = "ok" if step.ok else ("FAIL" if step.ok is False else "no result")
        cls = "ok" if step.ok else "fail"
        parts.append(
            f"<details id=s{step.n}><summary>#{step.n} {_e(step.tool)} "
            f"<span class={cls}>{status}</span></summary>"
        )
        eff = effects(step)
        if eff:
            parts.append(
                "<p class=tag>touches: "
                + ", ".join(f"{_e(e.kind)} {_e(e.path)} ({e.how})" for e in eff)
                + "</p>"
            )
        args = json.dumps(step.args, indent=2, sort_keys=True, ensure_ascii=False, default=str)
        parts.append(f"<b>args</b><pre>{_e(_cut(args, max_chars))}</pre>")
        if step.output is not None:
            parts.append(f"<b>output</b><pre>{_e(_cut(step.output, max_chars))}</pre>")
        if step.error:
            parts.append(f"<b>error</b><pre>{_e(_cut(step.error, 2000))}</pre>")
        parts.append("</details>")
    parts.append("</body></html>")
    return "".join(parts)
