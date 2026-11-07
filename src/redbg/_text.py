"""Text helpers for safely displaying untrusted trace content.

Traces contain whatever tools and models produced — including, possibly,
terminal control sequences. Printing them raw lets a crafted trace clear
the screen, rewrite earlier lines, retitle the window, or (on some
terminals) worse. Everything redbg prints from a trace goes through
``clean`` first.
"""

from __future__ import annotations

import re
import unicodedata

# Fast path: anything outside printable ASCII (plus \t, \n) is looked at.
_SUSPECT_RE = re.compile(r"[^\x20-\x7e\t\n]")
# Escaped categories: Cc (C0/C1 controls, DEL — incl. ESC and the 1-byte
# CSI \x9b), Cf (format chars: bidi overrides/isolates U+202A-202E and
# U+2066-2069, zero-width U+200B-200D, U+FEFF, soft hyphen...), Zl/Zp
# (U+2028/2029 line/paragraph separators) and Cs (lone surrogates, which
# crash a UTF-8 terminal write). \r is Cc, so it is escaped too: it lets a
# line overwrite itself.
_ESCAPE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})


def _escape(match: re.Match) -> str:
    ch = match.group(0)
    if unicodedata.category(ch) not in _ESCAPE_CATEGORIES:
        return ch
    code = ord(ch)
    if code <= 0xFF:
        return f"\\x{code:02x}"
    if code <= 0xFFFF:
        return f"\\u{code:04x}"
    return f"\\U{code:08x}"


def clean(text) -> str:
    """Return ``text`` as a string with invisible/control characters made visible.

    ``"\\x1b[2J"`` becomes the literal six characters ``\\x1b[2J`` and a
    right-to-left override becomes ``\\u202e`` — the content is preserved
    for debugging, but it can't drive the terminal or visually disguise
    one name as another (``"\\u202eelif_daer"`` no longer shows as
    ``read_file``). Side effect: emoji joined with U+200D (ZWJ) show the
    joiner escaped.
    """
    if not isinstance(text, str):
        text = str(text)
    return _SUSPECT_RE.sub(_escape, text)


def canonical_name(name) -> str:
    """Normalize a tool name for policy matching (``--forbid-tool``).

    NFKC folds compatibility forms (full-width ``ｄ`` → ``d``), format
    characters (zero-width, bidi) are dropped, then the result is
    case-folded — so ``Delete_File``, ``delete\\u200b_file`` and
    ``ｄelete_file`` all match ``delete_*``.
    """
    text = unicodedata.normalize("NFKC", str(name))
    text = "".join(ch for ch in text if unicodedata.category(ch) != "Cf")
    return text.casefold()


_NAMESPACE_SEP_RE = re.compile(r"__|[:/.]")


def name_variants(name) -> list[str]:
    """A tool name plus every namespace-stripped suffix of it, canonicalized.

    MCP and plugin hosts prefix tool names (``mcp__files__Delete_File``,
    ``files/delete_file``, ``server:delete_file``). A policy written for
    ``delete_*`` must still catch them, so matching tries the full name and
    each suffix after a ``__``, ``:``, ``/`` or ``.`` separator.
    """
    canon = canonical_name(name)
    variants = [canon]
    for match in _NAMESPACE_SEP_RE.finditer(canon):
        tail = canon[match.end() :]
        if tail and tail not in variants:
            variants.append(tail)
    return variants


def md_fence(text: str, lang: str = "") -> str:
    """Wrap ``text`` in a Markdown code fence it cannot break out of.

    The fence is one backtick longer than the longest backtick run inside
    the content (CommonMark rule), so tool output containing ```` ``` ````
    can't close the block early and inject Markdown/HTML into a report.
    """
    longest = max((len(m) for m in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return f"{fence}{lang}\n{text}\n{fence}"
