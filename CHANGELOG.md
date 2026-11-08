# Changelog

## 0.3.0 - unreleased

**Round 5 (evidence, privacy, observability):** details, scores and what could
not be tested: `docs/ROUND5.md`.

### Added
- **`--sarif FILE` on `check` and `audit`**: SARIF 2.1.0 for code-scanning
  dashboards (the tool block names `Calas Automations Inc.`).
- **`redbg otel TRACE [-o FILE] [--with-args]`**: OTLP/JSON spans (one root
  span per session, one per tool step). Deterministic ids; arguments left out
  unless asked for, and then redacted. Sends nothing anywhere.
- **`redbg digest TRACE [--expect SHA256] [--strict] [--json]`**: SHA-256 of
  the file plus timeline anomalies (duplicate event ids, timestamps going
  backwards, tool calls with no result). Still prints the hash of a file it
  cannot parse (exit 2).
- **Privacy flags for `redact` and `scan`**: `--paths` (user name in
  `/home/NAME`, `/Users/NAME`, `C:\Users\NAME`), `--also WORD` (repeatable,
  case-insensitive literal), and `--pii` now also covers IPv4 addresses (a
  dotted version number like `1.2.3.4` is caught too). All opt-in.
- `redbg.__author__`; `--help` footer names the publisher; `maintainers` in
  the package metadata.
- `bench/mutation_sanity.py` (breaks 20 conditions one at a time and checks
  the tests notice), golden files for every output format
  (`tests/golden`, refresh with `REDBG_UPDATE_GOLDEN=1`), a trace recorded by
  the published 0.1.1 as an upgrade-path fixture, `.gitattributes` (LF line
  endings so golden files and hashes survive a Windows checkout).

### Fixed
- A trace whose `call_id` / `id` was a list or object crashed loading with
  `TypeError: unhashable type` (exit 2 "unexpected TypeError"). Such ids are now
  matched by value.
- A trace with non-text `output` / `error`, or non-object `args`, crashed
  `why`, `replay --export-html` and `fork` with `TypeError`. They are coerced
  to text / `{"_args": ...}` and `fork` ignores unusable arguments and tool
  names instead of failing.
- The sdist now carries the golden files and fixtures its tests need.

**Round 4 (the stranger's first hour):**

PyPI still serves 0.1.1; 0.2.0 was never published, so 0.3.0 is the first
release containing everything below and the 0.2.0 / round 3 entries. Not a
drop-in upgrade from 0.1.1 (see the "Behaviour change" notes). Details,
scores and what could not be tested: `docs/ROUND4.md`.

### Added
- **`redbg demo [DIR]`**: writes two example traces, so `pip install redbg`
  users can try `diff` / `check` without cloning the repo.
- **`redbg sessions`**: lists recent Claude Code / Codex transcripts on this
  machine (newest first, `--dir`, `--limit`, `--json`).
- `python -m redbg` (same as the command); `py.typed` (the package is typed
  and `mypy src` is clean); `LICENSE` file shipped in the wheel and sdist;
  `--help` documents the exit codes.
- Project URLs (repository, issues, changelog), Python 3.9-3.13 and
  "Typing :: Typed" classifiers, SPDX license expression; `MANIFEST.in`
  (sdist carries tests, examples, bench and CHANGELOG).
- `.github/workflows/ci.yml`: tests on Linux/Windows/macOS x Python
  3.9/3.11/3.13, lint, type check, build + `twine check` + clean-wheel quick
  start (written, not yet run on GitHub).

### Fixed
- A console that cannot show a character (cp1252 redirect on Windows, ASCII
  container) crashed with a traceback and exit 1 - which CI reads as "rule
  violations". Such characters now print as `\uXXXX`.
- An unwritable output (`--export-md`, `--export-html`, `fork --save`, a
  folder given as a trace...) gave a traceback and exit 1; now one plain line
  and exit 2. File errors read "cannot open 'x': no such file or folder"
  instead of `[Errno 2] ...`. **Behaviour change**: any unexpected crash is
  now exit 2 with a one-line message (`REDBG_DEBUG=1` for the traceback)
  instead of a traceback with exit 1; Ctrl-C exits 130.
- `fork --tools FILE` whose code raises or calls `sys.exit()` now exits 2 with
  the error, instead of a traceback (or a silent exit 0 for `sys.exit(0)`).
- `redact -o` wrote straight into the destination: a bad line half-way left
  a truncated trace there. It now writes beside it and moves it into place
  when complete (as `import` already did); symlinked outputs and devices such
  as `/dev/null` still work.
- Written traces, reports and JUnit files always use `\n` line endings
  (Windows text mode wrote `\r\n`).
- Windows: replacing a file another program has open is retried briefly;
  ANSI colors are only used when the console accepts them.
- `bench/bench.py` no longer builds a shell command from the checkout path.
- 15 `mypy` errors (none changed behaviour).

**Round 3 (earlier, same unreleased version):**

Round 3 panel: incident responder, red-team attacker, privacy/compliance
auditor, Windows/cross-platform engineer, CI/DevOps engineer, performance
engineer, new-user docs reviewer. Two full passes (build, then adversarial
re-review of the new code).

### Added
- **`redbg audit TRACE`**: one pass over a whole session that ranks leads -
  `invented_path` (high when the tool answered "not found"), `destructive`
  (`rm -r`, `git reset --hard`, force push, SQL DROP/TRUNCATE, `curl | sh`,
  PowerShell `Remove-Item -Recurse`, ...), `retried_failure`, `failure_streak`,
  `loop`, `cycle`, `incomplete`, `secrets`. `--json`, `--min-severity`,
  `--no-secrets`, `--strict` (exit 1 on a high finding).
- **`check` policy rules**: `--forbid-path GLOB`, `--forbid-write GLOB`
  (file ledger, shell commands included), `--forbid-arg REGEX`,
  `--max-cycles N` (alternating loops of 2-8 calls), `--max-tokens N`
  (fails closed without usage data).
- **CI report formats**: `check --github` (workflow annotations, escaped so
  trace text cannot forge a command) and `check --junit FILE`.
- **Token usage**: new `usage` event; `Recorder.usage()`; Claude Code
  transcripts are read per message id (the repeated usage on each content
  block is counted once). `info` shows totals; `info --json` too.
- `find_cycles` API; `info` reports alternating cycles.
- `-` reads a trace from standard input; UTF-8 BOM, UTF-16 and UTF-32 files
  (PowerShell `>`) and misnamed gzip open directly.
- `redbg scan|redact --pii`: e-mail addresses and Luhn-valid card numbers.
- ~20 more secret shapes (see README "Secrets and safety").
- `info --json`.

### Fixed
- `--forbid-tool` / `--require-tool` missed namespaced names such as
  `mcp__files__Delete_File`: each name is now also tried without its
  `__`, `:`, `/` or `.` prefixes. **Behaviour change**: policies are
  stricter (fail-closed) for namespaced tools.
- Windows: `C:\dir\file` in shell commands lost its backslashes
  (`C:dirfile`); drive letters and `blame` lookups are case-insensitive;
  `cat a > b` reported `b` as a read; `git rm|mv|checkout --`, PowerShell
  verbs (`Remove-Item`, `Set-Content`, `Copy-Item`...), `curl -o`, `wget -O`
  now appear in `files`/`blame`; `$HOME/.env`-style paths are no longer
  dropped.
- Piping into `head` printed a `BrokenPipeError` traceback; now exits 141
  quietly (never 0/1/2).
- `redact` on a non-JSONL log gave a bare JSON error; now names the line and
  points to `redbg import --redact`.
- Diff of two long runs that start/end alike was super-linear (two identical
  26,000-step runs: `check` took 29 s, measured on a loaded host); the common
  head and tail are now trimmed before alignment (7 s, of which 3 s is loading).
- Redaction pre-filter: each default pattern is only run when its required
  literal is in the text (tested against a sample of every pattern, including
  Unicode case tricks). `bench/bench.py` now deletes its ~200 MB inputs.
- README quick-start output listed `rules: complete, baseline`; the real
  output includes `non_empty`.

**Round 2 (earlier, same unreleased version):**

Expert round 2 (agent-observability, transcript-format, security/privacy,
incident-response and TUI/DX reviews; skeptical-user pass).

### Added
- **Reads real transcripts directly**: Claude Code JSONL, Codex rollouts,
  OpenAI/Anthropic message arrays/JSONL (and `.gz`), auto-detected by
  every command (`replay`, `diff`, `check`, `fork`, `info`, `scan`...).
  Streaming, schema-drift tolerant, crash tolerant (cut-off last line ->
  status `truncated`, so `check` fails closed). `redbg import` now converts
  these too (`--redact`, atomic write).
- **`redbg why TRACE N`** (and `why` in the REPL): the prompt and model text
  behind a call, earlier steps in the turn, and where each concrete value in
  its arguments first appeared - or that it appeared nowhere. `--json`.
- **`redbg files` / `redbg blame TRACE PATH`**: file read/write/delete ledger
  per step (declared for edit tools and apply_patch, inferred for shell).
- **Breakpoints** in the REPL: `break` (tool glob, `fail`, `slow:MS`,
  `file:PATH`, `~REGEX`), `tb`, `c`, `rc`, `info break`, `delete`.
- **`replay --export-html`**: script-free, CSP-locked, escaped, redacted by
  default (`--no-redact-html` to opt out). `--redact` on every viewing
  command.
- **Time-to-first-view**: `replay --show N` on files over 4 MB stops reading
  after step N (counter shows `N/?`).
- `bench/`: deterministic generators + `bench/bench.py` (load time, peak
  memory, time-to-first-view, optional older git ref) and `RESULTS.md`.
- 47 new tests, including a mutation fuzz of hostile Claude Code / Codex
  logs.

### Changed
- Trace files are read with `errors="replace"`: a log cut mid-character now
  opens instead of failing with a decode error.
- `Session.load` accepts `max_steps`, `max_output_chars`, `redact`;
  `Session` gains `partial` and `format`. `load_events` is unchanged
  (native only); `iter_native` / `iter_any` stream.
- Version 0.3.0.

## 0.2.0 — unreleased

### Panel-review fixes (second pass)
- **Security (high):** the redactor missed free-text secrets and `scan`
  then reported "clean". Now redacted (and flagged by `scan`): the **whole**
  PEM private-key block (previously only the `BEGIN` line), `.env` /
  `export` / `KEY: value` assignments, `?api_key=…` query strings,
  `Authorization: Basic …`, and `Bearer` with any spacing or `Bearer:`.
  Key names are kept (`OPENAI_API_KEY=[REDACTED]`). All new patterns are
  linear-time on hostile input.
- `check` no longer passes an empty, garbage or crashed-before-first-call
  trace, or a run where no rule was evaluated; `--allow-empty` opts out.
- Deeply nested traces: Python 3.9 crashed (`RecursionError`, exit 1 =
  "violations"). Every recursive walk is now depth-limited (100 levels;
  deeper values become a marker, or `[REDACTED]` when redacting), JSON too
  deep to parse is a load error, and the CLI exits 2 instead of a traceback.
- Display spoofing: Unicode format characters (bidi overrides/isolates,
  zero-width chars, BOM), U+2028/2029 and lone surrogates are escaped
  (`\u202e`) in terminal output and Markdown reports.
- Non-string tool names (`123`, `null`) no longer crash `check`;
  `Step.tool` is always a `str`.
- `--forbid-tool` / `--require-tool` match case-insensitively after NFKC
  normalization with format characters removed (`Delete_File`,
  `delete\u200b_file` and full-width `ｄelete_file` all match `delete_*`).
  **Behaviour change** from the first 0.2.0 pass, which was case-sensitive.
- `@rec.wrap` records objects with `async def __call__` correctly, and
  rejects generator functions (sync/async) with a clear `TypeError` instead
  of recording the generator's repr.
- Redaction precision: `*_tokens_details` dicts and digit-only string
  counts (`"max_tokens": "1024"`) are kept; `secret_tokens`,
  `access_token_count` and similar are now redacted; shell `PWD=`/`OLDPWD=`
  lines are kept.
- `fork --save` refuses to overwrite the source trace (exit 2).
- Bare `pytest` now collects (tests imported `tests.conftest`; only
  `python -m pytest` worked).
- README redaction section rewritten to match the code exactly, with
  limits; "LCS" wording replaced by `difflib.SequenceMatcher`.


### Added
- `redbg check` — a CI gate. Compares a run against a `--baseline`
  (fails on any alignment change by default; `--fail-on` picks kinds,
  `output_changed` is opt-in) and enforces rules: session completed,
  `--max-steps`, `--max-failures`, `--max-repeats` (loop detector),
  `--forbid-tool` / `--require-tool` globs. Exit 0/1/2, `--json` output.
  Python API: `CheckRules`, `run_check`.
- `redbg diff --json` (`diff_to_dict`) and `--ignore-keys` for noisy args
  such as request ids and timestamps.
- `redbg info` reports runs of identical consecutive calls (possible
  loops); `find_repeats` in the API.
- `Recorder.wrap` supports `async def` tools.
- Secret patterns: OpenAI `sk-proj-`/`sk-svcacct-`/`sk-admin-`, GitHub
  `gho_/ghu_/ghs_/ghr_`, Stripe, Slack webhooks, Hugging Face, JWTs,
  `Bearer` header values, `user:password@` in URLs.

### Fixed
- **Security:** control characters from traces (ANSI/OSC escapes, C1
  CSI, `\r`) are escaped in all terminal output, so a crafted trace can
  no longer clear the screen, rewrite lines or retitle the terminal.
- **Security:** `--export-md` fences untrusted content with a fence
  longer than any backtick run inside it, and renders names as code
  spans — tool output can no longer inject Markdown/HTML into reports.
- **Data loss:** `redbg redact X -o X` (and `import`) truncated the input
  before reading it, leaving an empty file. They now refuse when the
  output is the same file (incl. symlinks / other spellings) and exit 2.
- Async tools wrapped with `@rec.wrap` recorded the coroutine object's
  repr instead of the result.
- OpenAI project keys (`sk-proj-…`) were not redacted.
- Numeric usage fields (`max_tokens`, `prompt_tokens`, `token_count`, …)
  and `author`/`authority` keys were wrongly redacted.
- Diff treated `1` and `1.0` as different args; non-object args (lists)
  could crash the args-change summary.
- `redbg scan`/`redact` on a missing file now exit 2 with a message
  instead of a traceback.

### Changed
- Diff signatures are canonicalized (integral floats == ints). Runs that
  differed only by `1` vs `1.0` now compare equal.
- Markdown export: step headings render the tool name as a code span;
  steps with no result say "no result" instead of "FAIL".
- Repository: the accidentally committed `.venv/`, `*.egg-info` and
  `__pycache__` were removed from version control; `.gitignore` added.

## 0.1.1
- Initial public release: record, replay, diff, fork, redact, scan, import.
