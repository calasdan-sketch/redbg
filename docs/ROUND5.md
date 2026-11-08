# Round 5 - evidence, privacy, observability

Question for this round: what would a session-forensics engineer, a privacy
officer and an observability engineer ask of redbg that rounds 1-4 did not?
Everything below was run in this checkout (Linux, Python 3.11 / 3.13; no
network use except read-only registry and schema downloads). Nothing was
published, uploaded, tagged or pushed. Only synthetic traces were used; no
real session transcript on this machine was read.

## How this review was done (honest)

No sub-agent tool was available in this session, so **one reviewer played every
role in turn**; each role is a separate pass with its own commands, not an
independent person. Pass A found and fixed; pass B re-attacked the new code,
re-read the diff, and re-ran the quick start from a freshly built wheel in a
clean virtual environment.

## Author line

Maintainer/author name everywhere is exactly `Calas Automations Inc.`.
Proof, from the freshly built wheel (`python -m build`, then
`unzip -p dist/redbg-0.3.0-py3-none-any.whl 'redbg-0.3.0.dist-info/METADATA'`):
`Author: Calas Automations Inc.` and `Maintainer: Calas Automations Inc.`
(`maintainers` was missing before). Also set: LICENSE (`Copyright (c) 2026
Calas Automations Inc.`, already right), `redbg.__author__`, the `--help` footer,
SARIF `tool.driver.organization`, OTLP resource attribute `redbg.publisher`.
`docs/ROUND4.md` had one old-state sentence with the short name; reworded.
A test (`test_author_string_is_pinned_everywhere`,
`test_no_stale_owner_label_in_tracked_text`) pins the string and fails on any
short form of the name (without the "Inc." suffix) in tracked text (the web address
`calasautomations.com` is a different spelling and is left alone). The package
metadata keeps the GitHub URLs added in round 4. **Whether that repository is
public could not be checked from here** (github.com answered 403 through the
build proxy); if it is private, delete the Repository, Issues and Changelog
lines from `[project.urls]` before releasing. No e-mail address exists or was
added.

## Specialists and findings

| role | what it did (command) | finding | fixed? |
|---|---|---|---|
| Upgrade-path tester | `pip download redbg==0.1.1 --no-deps`, unzip, record a session with the 0.1.1 `Recorder`, then run `info / diff / audit / scan / why / redact / check / otel / digest` from this tree on it | every command reads a 0.1.1 trace; schema `v` is still 1; there are no config or state files, so nothing to migrate. (`check` of that trace fails "step has no result" only because the throw-away fixture first left a call open - correct behaviour) | no change needed; the trace is now a committed fixture (`tests/fixtures/redbg_0_1_1_session.jsonl`) and a test |
| Forensics / replay engineer | hypothesis fuzz (700 schema-valid but type-hostile traces) through load, `why`, `files`, `blame`, `diff`, `fork`, HTML export, plus new exports | **`"call_id": []` (any list/object id) crashed loading** with `TypeError: unhashable type` (exit 2 "unexpected TypeError"); non-text `output`/`error` crashed `why` and `--export-html`; non-object `args` or a list as tool name crashed `fork` | yes: ids matched by value, output/error coerced to text, args to `{"_args": ...}`, `fork` ignores unusable args/names |
| Forensics / replay engineer | asked "is this file the one I saved, and was it spliced?" | nothing in redbg could say | yes: `redbg digest` (SHA-256, duplicate event ids, timestamps going backwards, open calls, `--expect`, `--strict`); also fingerprints files it cannot parse |
| Forensics / replay engineer | tried `--sarif`, `-o`, `--junit` pointed at the input trace | a typo could overwrite the trace being reported on (`--junit` had the same flaw since round 3) | yes: all report writers refuse to overwrite an input (exit 2, plain line) |
| Privacy officer | synthetic Claude Code transcript with `/home/alice/...`, `C:\Users\Carl`, an IPv4, an e-mail, a company name; ran `redact --pii` | secrets and e-mail gone, but **user names in home paths, IP addresses and company/person names stayed**; and `import --redact` / `--export-html` never apply opt-in layers | yes: `--paths`, `--also WORD`, IPv4 in `--pii`; README says plainly which commands apply which layers; output keeps the input's format (tested for Claude Code and Codex) |
| Privacy officer | `scan` on the redacted output with the same flags | must come back clean, or redaction is not idempotent | property tests (below) + `test_paths_pii_and_also_redact_and_scan_comes_back_clean` |
| Privacy officer | `--also red` | would corrupt the `[REDACTED]` marker | refused with a plain message (exit 2); 1-character and empty terms refused |
| Observability engineer | wanted traces in an OTLP tool and findings in a code-scanning tab | only JUnit/GitHub annotations existed | yes: `redbg otel` (OTLP/JSON, deterministic ids, args off by default and redacted if requested, no network) and `--sarif` on `check`/`audit` |
| Observability engineer | validated 4 generated SARIF files (check with violations, audit with a step-located finding, audit with a secrets finding, and the two golden files) against the published SARIF 2.1.0 JSON schema (downloaded read-only from schemastore, `jsonschema` in a scratch venv) | 0 schema errors | - (whether GitHub's upload accepts a result without a line number: not tried) |
| QA / test-methodology | `pip install hypothesis` in a scratch venv; properties: an embedded key never survives (adjacent or spaced), redaction is idempotent, `scan` after `redact` is clean, nested events idempotent, 3000-4000 cases each | all hold; no redaction defect found. The same properties now run as seeded tests with no new dependency | tests added |
| QA / test-methodology | `bench/mutation_sanity.py`: 20 one-line condition flips in `redact`, `check`, `replay`, `schema`, `sarif`, `otlp`, `forensics`, `cli`, `_fs` | first run 19/20 noticed; the 20th was a stale search string in my script. After fixing it, 20/20 noticed | script committed |
| QA / test-methodology | golden files for every output format | 18 golden outputs (check json/text/github/junit/sarif, audit json/text/sarif, info, diff text/json, otel, otel with args, digest, files, why, Markdown and HTML export) | `tests/golden`, refresh with `REDBG_UPDATE_GOLDEN=1` |
| Release engineer | `python -m build`, `twine check`, clean venv install, quick start from a folder with a space in its name, sdist extracted and its tests run | wheel/sdist PASSED; sdist test run initially lacked the golden/fixture files | MANIFEST.in fixed; 437 tests pass from the sdist |
| Windows reviewer (static only) | read new file writes and path code | goldens and hashes would break under CRLF checkout; `os.path.relpath` can raise on another drive | `.gitattributes` (LF), `ValueError` caught in the SARIF path helper. **Not run on Windows** |
| Competitor's maintainer | PyPI JSON of `rewind-agent` 0.17.1 and `claude-code-log` 1.7.0, read-only, 2026-11-08 | both pages unchanged in shape; neither description mentions SARIF, OpenTelemetry, redaction or hashing (0 matches each). Repositories not read | README comparison row added with that exact wording |
| Lint / type / locale | `ruff check .`, `mypy src` (scratch venv), `PYTHONIOENCODING=ascii` run of the new commands | clean; ascii console works | - |

## Scored ideas (value / differentiation / effort / risk each 1-5; effort 5 = most work, risk 5 = riskiest)

| # | idea | value | diff. | effort | risk | status |
|---|---|---|---|---|---|---|
| 1 | SARIF for `check`/`audit` (round 4 #18) | 4 | 4 | 3 | 2 | DONE |
| 2 | `redbg otel` OTLP/JSON export | 4 | 4 | 3 | 2 | DONE |
| 3 | `redbg digest` fingerprint + anomalies | 4 | 4 | 2 | 1 | DONE |
| 4 | `--paths` (home-folder user names) | 4 | 4 | 2 | 2 | DONE |
| 5 | `--also WORD` literal redaction | 4 | 3 | 1 | 2 | DONE |
| 6 | IPv4 in `--pii` | 3 | 2 | 1 | 2 | DONE |
| 7 | Crash fixes for hostile ids / output / args | 5 | 1 | 2 | 1 | DONE |
| 8 | Report writers never overwrite inputs | 4 | 1 | 1 | 1 | DONE |
| 9 | Golden files for every output format | 4 | 1 | 2 | 1 | DONE |
| 10 | Mutation sanity script | 3 | 1 | 2 | 1 | DONE |
| 11 | Upgrade-path fixture from the published 0.1.1 | 4 | 1 | 1 | 1 | DONE |
| 12 | Seeded property tests (no new dependency) | 4 | 1 | 2 | 1 | DONE |
| 13 | Author line, `maintainers`, pinned by test | 5 | 1 | 1 | 1 | DONE |
| 14 | `.gitattributes` (LF) + sdist carries test data | 3 | 1 | 1 | 1 | DONE |
| 15 | `Recorder` append / no-overwrite option (r4 #17) | 3 | 2 | 2 | 3 | NOT-DONE (default change would break callers) |
| 16 | Reusable GitHub Action / pre-commit hook (r4 #19) | 4 | 3 | 3 | 3 | NOT-DONE (own repo; Dan's call) |
| 17 | Trusted publishing + provenance (r4 #20) | 4 | 2 | 2 | 2 | NOT-DONE (needs a PyPI setting only Dan can change) |
| 18 | Cost in money from tokens (r4 #21) | 3 | 3 | 2 | 4 | NOT-DONE (needs vendor prices; never invented) |
| 19 | Framework auto-instrumentation (r4 #22) | 4 | 3 | 5 | 4 | NOT-DONE |
| 20 | Web/TUI viewer (r4 #23) | 3 | 3 | 5 | 3 | NOT-DONE |
| 21 | Multi-agent step views (r4 #24) | 3 | 4 | 5 | 3 | NOT-DONE |
| 22 | Shell completion (r4 #25) | 2 | 1 | 2 | 1 | NOT-DONE |
| 23 | `audit` across many sessions (r4 #26) | 4 | 4 | 3 | 2 | NOT-DONE (must never read transcripts unasked) |
| 24 | Signed / hash-chained recording (real tamper evidence) | 4 | 4 | 4 | 3 | NOT-DONE (needs key handling; `digest` is accident detection only) |
| 25 | Stable pseudonyms (`[REDACTED:ab12]`) so redacted diffs still correlate | 3 | 4 | 3 | 3 | NOT-DONE (short secrets make hashes guessable; needs a salt design) |
| 26 | Name/address detection in prose (NER) | 3 | 3 | 5 | 4 | NOT-DONE (needs a model or dependency; `--also` covers known names) |
| 27 | `redact --report` (counts per reason) | 2 | 2 | 2 | 1 | NOT-DONE |
| 28 | Push OTLP to a collector | 2 | 1 | 3 | 4 | NOT-DONE (network; by design redbg sends nothing) |
| 29 | SARIF line regions (needs line numbers kept by the loader) | 3 | 2 | 3 | 2 | NOT-DONE |
| 30 | Try the SARIF upload on GitHub code scanning | 3 | 1 | 1 | 1 | NOT-DONE (needs a push) |

## Numbers

Tests: 381 before this round, 437 after (`python -m pytest`; also green on
Python 3.11 and, from the extracted sdist, on 3.13). `ruff check .` clean,
`mypy src` clean. Benchmark (`bench/RESULTS.md`, 100 MB inputs, committed
numbers): see the file. The host was heavily loaded (load average ~9-11) so
single runs scatter widely; an interleaved A/B of the round 4 and round 5 code
on 25 MB inputs is reported next.

Interleaved A/B, round 4 commit `d075e74` vs this tree, 25 MB synthetic inputs,
3 runs each (min / median seconds; load average ~10):

| command | input | round 4 | round 5 |
|---|---|---|---|
| `audit` | redbg native | 22.3 / 26.7 | 24.7 / 25.9 |
| `why` (step 500) | redbg native | 0.93 / 0.95 | 0.93 / 1.04 |
| `info` | redbg native | 1.04 / 1.12 | 1.17 / 1.22 |
| `audit` | Claude Code | 12.0 / 13.3 | 9.8 / 11.3 |
| `why` (step 500) | Claude Code | 1.01 / 1.10 | 1.02 / 1.10 |
| `info` | Claude Code | 0.43 / 0.83 | 0.44 / 0.56 |

No consistent change; `info` on the native file is about 8-10% slower in both
min and median, which may be real (a hashability check per event) or noise on
this busy host - I did not chase it. The 100 MB table in `bench/RESULTS.md`
shows the new `otel` (about 5.5 s) and `digest` (about 4-4.5 s) commands; the
slower-looking `current` rows there were measured first, before the
baseline, under varying load, and are not a reliable comparison.

## What could not be tested

- **Windows and macOS: nothing was run.** Fixes are from reading the code; the
  CI workflow (written in round 4, still never run) would be the first test.
- Python 3.9 and 3.10 were not installed (3.11, 3.12 and 3.13 were).
- Real Claude Code / Codex transcripts: deliberately not used; every fixture
  is synthetic (secret-shaped strings are assembled at run time).
- GitHub code scanning: the SARIF output was checked against the published
  schema only, never uploaded.
- OTLP/JSON: structure follows the protocol's JSON encoding as I know it
  (hex ids, nanosecond strings, numeric status codes); no collector or
  OpenTelemetry library was available here to load it. Treat as unverified
  against a real consumer.
- `pip install redbg` from the real index after release; competitor
  repositories (only their PyPI pages were read).
