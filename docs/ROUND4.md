# Round 4 - the stranger's first hour

Question for this round: what does someone get who types `pip install redbg`
and follows only the README? Everything below was run for real in this
checkout (Linux, Python 3.9 / 3.11 / 3.13 installed, no network use except
read-only registry lookups). Nothing was published, uploaded, tagged or pushed.

## How this review was done (honest)

No sub-agent tool was available in this session, so **one reviewer played
every role in turn**; the roles below are separate passes with separate
commands, not independent people. Round 3's remaining gaps ("not built" list:
SARIF, GitHub Action, auto-instrumentation, UI) were re-scored, not skipped.
Pass A found and fixed; pass B re-attacked the new code and re-ran the quick
start from a freshly built wheel.

## Specialists and findings

| role | what it did (command) | finding | fixed? |
|---|---|---|---|
| First-time user (README only) | built wheel, `pip install` into fresh venvs (3.9, 3.11, 3.13), ran README quick start from a folder with a space in its name | README said "from a clone of this repo" - the two sample traces are not in the wheel, so the 30-second try-it cannot work after `pip install` | yes: `redbg demo` |
| First-time user | `python -m redbg --version` | `No module named redbg.__main__` | yes |
| First-time user | `redbg diff nope.jsonl x.jsonl` | `redbg: [Errno 2] No such file or directory: 'nope.jsonl'` | yes: "cannot open 'nope.jsonl': no such file or folder" |
| First-time user | asked "where are my transcripts?" | README only said `~/.claude/projects/<project>/<session>.jsonl` | yes: `redbg sessions` |
| Release engineer | `python -m build`, `twine check`, `unzip -l`, `tar tzf` | **no LICENSE file** in wheel or sdist although metadata says MIT; no `py.typed`; license in the old `{text=}` form; only a Homepage URL; no Python/OS classifiers; author name lacked the "Inc." suffix the registry shows | yes (LICENSE, SPDX `license = "MIT"` + `license-files`, URLs, classifiers, author, `py.typed`, MANIFEST.in) |
| Release engineer | `pip index versions redbg`, PyPI JSON (read-only) | registry has only **0.1.1** (2026-10-22); repo is 0.3.0; 0.2.0 was never published; two `0.3.0` headings in CHANGELOG | CHANGELOG now one heading; checklist explains the jump |
| Release engineer | built from the working tree | an old ignored `build/` folder exists in the checkout; building from it can leak stale files | checklist says build from a clean clone |
| Supply-chain reviewer | grep of wheel+sdist for personal paths, mails, keys | clean except a comment mentioning `/home/dan` | comment changed; zero runtime dependencies confirmed (`pip list` in clean venvs shows only redbg) |
| Supply-chain reviewer | read `.github` (none), `bench.py` | `bench.py` built a shell command from the checkout path (`shell=True`); no CI at all | yes: argument list + tarfile; CI file added (unrun) |
| Hostile-input fuzzer | `PYTHONIOENCODING=ascii/cp1252 redbg diff ...` | **traceback + exit 1** (CI reads exit 1 as "rule violations") on any console that cannot show the report's symbols | yes: unencodable characters print as `\uXXXX` |
| Hostile-input fuzzer | export/save to `file/x` (parent is a file), folder as trace, `--tools` file that raises or calls `sys.exit(0)` | tracebacks with exit 1; `sys.exit(0)` in a tools file made `fork` exit **0** silently | yes: exit 2 + one plain line |
| Hostile-input fuzzer | 120 MB single line; 300k garbage lines with `--skip-bad`; 16 threads x 300 calls on one Recorder | huge line: clean exit 2 in 7.6 s; garbage: `check` fails closed (exit 1, "no tool steps"); threads: 4800 steps, all numbered uniquely | nothing needed |
| Hostile-input fuzzer | ran as an unprivileged user against a read-only folder | clean exit 2 messages; but the redact error named `out.jsonl.part` | yes (names the real file) |
| Windows reviewer (static only) | read every `open`, `os.replace`, `shell=True`, `signal`, `\\`, newline use | text-mode writes would emit `\r\n` into JSONL/Markdown/JUnit; `os.replace` onto a locked file raises; ANSI codes on legacy consoles; cp1252 console crash (above) | yes (all four). **Not run on Windows.** |
| Data-safety reviewer | `redbg redact` with a bad line half-way | left a **truncated output file** at the destination | yes: stage beside, move when complete; symlink and `/dev/null` outputs still work |
| Docs/DX writer | compared README claims to real output | exit codes undocumented; `Recorder` silently replaces an existing trace path | documented in README and `--help` |
| CI/CD integrator | read `check` flags and exit paths | an internal crash exits 1, the same as "violations" | yes: crashes exit 2 (`REDBG_DEBUG=1` for traceback) |
| Type/lint | `ruff check .`, `mypy src` | ruff clean; mypy had 15 errors (no behaviour bugs) | yes, mypy clean now |
| Performance engineer | `bench/bench.py --baseline 6f8ad30` (round 3 commit) | see "Numbers" | no regression expected: only I/O edges changed |
| Competitor's maintainer | PyPI JSON of `rewind-agent`, `claude-code-log`, `claude-code-transcripts` (read-only, 2026-11-07) | rewind 0.17.1 unchanged ("Chrome DevTools for AI agents", native binary downloaded on first use); claude-code-log 1.7.0 needs Python >=3.10 plus click, dateparser, gitpython, jinja2, pydantic; claude-code-transcripts 0.6 needs >=3.10. Their repositories were not reachable, so feature claims beyond the PyPI pages stay as in the README | README comparison updated with the dependency facts |

## Scored ideas (value / differentiation / effort / risk each 1-5; effort 5 = most work, risk 5 = riskiest)

| # | idea | value | diff. | effort | risk | status |
|---|---|---|---|---|---|---|
| 1 | `redbg demo` (examples inside the wheel) | 5 | 3 | 1 | 1 | DONE |
| 2 | `redbg sessions` (find your transcripts) | 4 | 4 | 1 | 1 | DONE |
| 3 | Console-encoding crash fix | 5 | 1 | 1 | 1 | DONE |
| 4 | Crashes exit 2 not 1; plain file errors; Ctrl-C 130 | 5 | 2 | 2 | 2 | DONE |
| 5 | LICENSE + SPDX + URLs + classifiers + author | 5 | 1 | 1 | 1 | DONE |
| 6 | `py.typed` + mypy clean | 3 | 2 | 2 | 1 | DONE |
| 7 | `python -m redbg` | 3 | 1 | 1 | 1 | DONE |
| 8 | Atomic `redact -o` | 4 | 2 | 1 | 2 | DONE |
| 9 | LF newlines everywhere written | 3 | 1 | 1 | 1 | DONE |
| 10 | Windows lock retry + ANSI gating | 3 | 1 | 2 | 2 | DONE (unrun on Windows) |
| 11 | Exit codes in `--help` and README | 4 | 1 | 1 | 1 | DONE |
| 12 | `--tools` file errors/`sys.exit` handled | 3 | 1 | 1 | 1 | DONE |
| 13 | Version/metadata consistency test | 3 | 1 | 1 | 1 | DONE |
| 14 | CI workflow (3 OS x 3 Python, build, clean-wheel quick start) | 5 | 1 | 2 | 2 | DONE (written, never run: needs a push) |
| 15 | MANIFEST.in so the sdist is testable | 2 | 1 | 1 | 1 | DONE |
| 16 | `bench.py` without `shell=True` | 2 | 1 | 1 | 1 | DONE |
| 17 | `Recorder(..., append/no-overwrite)` option | 3 | 2 | 2 | 3 | NOT-DONE (documented instead; changing the default would break callers) |
| 18 | SARIF output for `audit`/`check` (code-scanning tab) | 4 | 4 | 3 | 2 | NOT-DONE |
| 19 | Reusable GitHub Action / pre-commit hook | 4 | 3 | 3 | 3 | NOT-DONE (needs its own repo; Dan's call) |
| 20 | Trusted publishing (OIDC) + provenance for releases | 4 | 2 | 2 | 2 | NOT-DONE (needs a PyPI/GitHub setting only Dan can change) |
| 21 | Cost in money from tokens | 3 | 3 | 2 | 4 | NOT-DONE (needs vendor prices; rule: never invent them) |
| 22 | Framework auto-instrumentation | 4 | 3 | 5 | 4 | NOT-DONE |
| 23 | Web/TUI viewer | 3 | 3 | 5 | 3 | NOT-DONE |
| 24 | Multi-agent step views | 3 | 4 | 5 | 3 | NOT-DONE |
| 25 | Shell completion | 2 | 1 | 2 | 1 | NOT-DONE |
| 26 | `audit` across many sessions (`sessions` + `audit` in one go) | 4 | 4 | 3 | 2 | NOT-DONE (next round; needs care so it never reads transcripts without being asked) |

## Numbers

Tests: 355 passing before this round, 381 after (`python -m pytest`; also
green on Python 3.9, 3.11 and 3.12). `ruff check .` clean; `mypy src` 15 errors ->
0. Benchmark: see `bench/RESULTS.md` (run with `--baseline 6f8ad30`, so the
round 3 code and this round's code were timed in the same run on the same
loaded host, load average ~9-11). Result: no measurable change - the two
columns differ in both directions (time to first view 0.27 s vs 0.12 s native,
0.44 s vs 0.41 s Claude Code; `check` 5.9 s vs 7.1 s and 5.9 s vs 4.2 s), which
is host noise; a 15-run interleaved `redbg --version` start-up comparison also
showed no difference. Peak memory identical (195 MB / 108 MB). No claim of a
speed-up or slow-down is made.

## What could not be tested

- **Windows and macOS: nothing was run.** Fixes are from reading the code.
  The new CI file would be the first real test.
- Python 3.10 was not available (3.9, 3.11, 3.12 and 3.13 were installed and tested). Linux only.
- `pip install redbg` from the real index: the wheel was installed from the
  local build only. After release, run the quick start once from a clean
  machine.
- GitHub Actions workflow: written only; action versions (`@v4`, `@v5`) are
  tags I did not look up today.
- Real Claude Code / Codex transcripts: deliberately not used on this
  machine; `sessions` was tested with a synthetic home folder.
- Competitor repositories (rewind and the two viewers): only their PyPI
  pages were readable.
