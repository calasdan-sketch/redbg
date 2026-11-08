"""Evidence helpers: a fingerprint of a trace file plus ordering anomalies.

``digest`` answers "is this the same file I saved yesterday, and does its
timeline hang together?" It reads the file; it never modifies it.
"""

from __future__ import annotations

import hashlib

from .formats import _epoch


def file_sha256(path: str) -> tuple[str, int]:
    """(hex digest, size in bytes) of the file exactly as stored on disk."""
    h = hashlib.sha256()
    size = 0
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
    return h.hexdigest(), size


def digest_session(session) -> dict:
    """Timeline facts and anomalies of a loaded session."""
    ids: dict = {}
    dup_ids = 0
    backwards = 0
    prev = None
    first = last = None
    unparsed = 0
    for event in session.events:
        eid = event.get("id")
        if isinstance(eid, str):
            if eid in ids:
                dup_ids += 1
            ids[eid] = True
        ts = _epoch(event.get("ts"))
        if ts is None:
            unparsed += 1
            continue
        if prev is not None and ts < prev:
            backwards += 1
        prev = ts
        first = ts if first is None else min(first, ts)
        last = ts if last is None else max(last, ts)
    open_steps = sum(1 for s in session.steps if s.result is None)
    return {
        "format": session.format,
        "events": len(session.events),
        "steps": len(session.steps),
        "open_steps": open_steps,
        "first_ts": first,
        "last_ts": last,
        "duplicate_event_ids": dup_ids,
        "timestamps_going_backwards": backwards,
        "events_without_usable_timestamp": unparsed,
    }


def anomalies(info: dict) -> list[str]:
    out = []
    if info["duplicate_event_ids"]:
        out.append(f"{info['duplicate_event_ids']} duplicate event id(s) (spliced or replayed lines?)")
    if info["timestamps_going_backwards"]:
        out.append(f"{info['timestamps_going_backwards']} event(s) timestamped earlier than the one before")
    if info["open_steps"]:
        out.append(f"{info['open_steps']} tool call(s) with no result (cut off?)")
    if info["events"] == 0:
        out.append("no events")
    return out
