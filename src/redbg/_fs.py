"""Small file-system helpers that behave the same on Linux, macOS and Windows."""

from __future__ import annotations

import os
import time


def replace_file(tmp: str, dst: str, attempts: int = 5) -> None:
    """``os.replace`` that tolerates Windows briefly locking ``dst``.

    On Windows, replacing a file another process (an antivirus scanner, an
    indexer, a viewer) has open fails with ``PermissionError``. A short retry
    clears the common case; a persistent failure is raised as is.
    """
    for attempt in range(attempts):
        try:
            os.replace(tmp, dst)
            return
        except PermissionError:
            if os.name != "nt" or attempt == attempts - 1:
                raise
            time.sleep(0.05 * (attempt + 1))


def explain_oserror(exc: OSError) -> str:
    """One plain-English line for a file error (no ``[Errno 2]`` noise)."""
    name = exc.filename if exc.filename is not None else None
    where = f" {name!r}" if name is not None else ""
    if isinstance(exc, FileNotFoundError):
        return f"cannot open{where}: no such file or folder"
    if isinstance(exc, IsADirectoryError):
        return f"{name!r} is a folder, not a trace file" if name else "that is a folder"
    if isinstance(exc, NotADirectoryError):
        return f"cannot use{where}: part of the path is a file, not a folder"
    if isinstance(exc, PermissionError):
        return f"no permission to use{where} (is it open in another program, or read-only?)"
    return f"cannot use{where}: {exc.strerror or exc}"


def staging_path(dst: str) -> str:
    """Where to write before moving into place at ``dst``.

    Normally ``dst + ".part"``. If ``dst`` exists and is not a regular file
    (``/dev/stdout``, a named pipe, ``NUL``) it is written directly: replacing
    a device node with a file would be wrong.
    """
    if os.path.exists(dst) and not os.path.isfile(dst):
        return dst
    # Follow a symlinked output so the target file is replaced, not the link.
    return os.path.realpath(dst) + ".part"


def name_target(exc: OSError, tmp: str, dst: str) -> OSError:
    """Make an error about the staging file name the real output file."""
    if exc.filename == tmp:
        exc.filename = dst  # name the file the user asked for, not ".part"
    return exc


def finish(tmp: str, dst: str) -> None:
    """Move a completed staging file into place (no-op when written directly)."""
    if tmp != dst:
        replace_file(tmp, tmp[: -len(".part")])
