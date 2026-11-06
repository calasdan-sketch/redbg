"""redbg — gdb for agent sessions.

Record tool-calling agent sessions to JSONL, then replay them like a
debugger: step through tool calls, inspect prompts/responses, diff two
runs, and fork a session at any step to explore what-if scenarios.
"""

from .check import CheckResult, CheckRules, run_check
from .diff import (
    align_steps,
    diff_to_dict,
    find_divergence,
    find_repeats,
    normalize_args,
    render_diff,
)
from .fork import ForkSpec, fork_session
from .importer import import_events
from .recorder import Recorder
from .redact import redact_event, redact_file, scan_file
from .replay import Navigator, Session, Step
from .schema import SCHEMA_VERSION

__version__ = "0.2.0"

__all__ = [
    "SCHEMA_VERSION",
    "Recorder",
    "Session",
    "Step",
    "Navigator",
    "align_steps",
    "find_divergence",
    "render_diff",
    "diff_to_dict",
    "find_repeats",
    "normalize_args",
    "CheckRules",
    "CheckResult",
    "run_check",
    "ForkSpec",
    "fork_session",
    "import_events",
    "redact_event",
    "redact_file",
    "scan_file",
    "__version__",
]
