# redbg — gdb for agent sessions

**Open any agent transcript — Claude Code, Codex, OpenAI/Anthropic message
logs, or your own — find the exact step where it went wrong, ask *why* it did
that, and fail CI when it happens again.** Local files, no account, no server,
zero dependencies. A 100 MB transcript shows its first step in well under a second
(0.07-0.10 s on a quiet machine, measured).

Record tool-calling agent sessions, then debug them like a program:
**step** forward/back through tool calls, **inspect** the exact
prompt/response at each step, **audit** a whole session for the suspicious
steps (invented paths, destructive commands, loops), **diff** two runs to
find where they diverged, **fork** a session at any step to explore what-if
scenarios, and **check** a run against a known-good baseline and a written
policy (forbidden tools, files and commands, token budget) in CI.

```
$ redbg diff monday.jsonl tuesday.jsonl

✗ First divergence at A:3 / B:3: same tool 'read_file' with same args,
  but A succeeded and B FAILED

    A      B     tool (A → B)                  note
───────────────────────────────────────────────────────────────────────
    1      1  =  read_file                     output same
    2      2  =  read_file                     output same
    3      3  ≠  read_file                     status changed; output DIFFERS
    4      4  ~  exec                          args changed; output DIFFERS

── args diff at divergence ──
...
```

## Debug a real session (Claude Code, Codex, message logs)

No conversion step: every command reads these formats directly (auto-detected,
`.gz` too).

```bash
redbg replay ~/.claude/projects/<project>/<session>.jsonl   # step through it
redbg audit session.jsonl         # where should I look first?
redbg why   session.jsonl 42      # why was call 42 made?
redbg blame session.jsonl src/app.py   # which steps touched this file?
redbg files session.jsonl         # every file read / written / deleted
redbg replay session.jsonl --export-html report.html   # share-safe page
```

```
$ redbg why session.jsonl 42      # illustrative output
── why step 42: Read ──
user asked:
Fix the bug in main.py
model said just before:
Let me check the config.
earlier steps in this turn:
  38:Bash, 39:Grep, 40:Read, 41:Bash (FAIL)
where the values in this call came from:
  <- main.py                  prompt
  <- config/app.yaml          step 39 output
  ?? /etc/invented/path.cfg   not found in anything the agent had seen (invented, or hidden by output truncation)
effects:
  read /etc/invented/path.cfg (declared)
```

`audit` reads the whole session once and lists what deserves a human look,
most serious first (illustrative output):

```
$ redbg audit session.jsonl
audit: 4 finding(s) in session.jsonl
  HIGH   destructive     step 31   Bash: git push --force
  HIGH   invented_path   step 42   Read: '/etc/invented/path.cfg' appears nowhere the agent had seen and the call failed with a not-found error
  HIGH   retried_failure step 50   'Bash' failed 6x in a row with identical arguments (steps 50-55)
  MEDIUM cycle           step 60   pattern [Read -> Edit] repeated 4x (steps 60-67)
  leads, not verdicts: check with `redbg why TRACE N`
```

Findings: `invented_path`, `destructive` (`rm -r`, `git reset --hard`,
force push, SQL `DROP`/`TRUNCATE`, `curl | sh`, PowerShell `Remove-Item
-Recurse`, ...), `retried_failure`, `failure_streak`, `loop`, `cycle`,
`incomplete`, `secrets`. `--json`, `--min-severity`, `--no-secrets`
(skips the slowest part), and `--strict` (exit 1 on any high finding).
They are leads, not verdicts: see Limitations.

`why` answers the incident question — *where did the agent get this value?* —
by searching what it had seen before the call (prompts, its own text, earlier
arguments and outputs). A value found nowhere is the classic invented path,
URL or ID. It is substring matching, not mind reading: see Limitations.

**Breakpoints** in the replay REPL, like gdb: `break Bash`, `break fail`,
`break file:src/app.py` (steps that touch that file), `break slow:5000`,
`break ~regex`, then `c` (continue) or `rc` (reverse-continue); `tb` sets a
one-shot breakpoint; `why`, `files` and `blame PATH` work at the prompt.

**Safe to share.** `--export-html` writes one self-contained page with no
scripts, no external resources and a strict Content-Security-Policy; all
trace text is escaped and secrets are redacted unless you pass
`--no-redact-html`. `--redact` on any command scrubs what is displayed.
Redaction runs on the full text *before* long outputs are cut, so a cut can
never leave half a private key behind.

## Install

```bash
pip install redbg
redbg --version          # also works as: python -m redbg --version
```

Python 3.9+ (tested on 3.9, 3.11, 3.12 and 3.13 on Linux). No runtime
dependencies, so it installs anywhere. Not yet run on Windows or macOS by the
author (see "Windows" below).

**Try it in 30 seconds** (nothing to clone; `redbg demo` writes two small
example traces):

```bash
redbg demo                      # writes ./redbg-demo/sample-a.jsonl and sample-b.jsonl
redbg diff  redbg-demo/sample-a.jsonl redbg-demo/sample-b.jsonl
redbg check redbg-demo/sample-b.jsonl --baseline redbg-demo/sample-a.jsonl; echo "exit=$?"
```

```
✗ check FAILED: redbg-demo/sample-b.jsonl vs baseline redbg-demo/sample-a.jsonl
  [divergence] First divergence at A:— / B:1: step added in B ('read_file')
  [added] baseline:— / candidate:1 'read_file': added
  rules: non_empty, complete, baseline
exit=1
```

Have Claude Code or Codex on this machine? `redbg sessions` lists your recent
transcripts (newest first); then `redbg audit PATH`.

**Exit codes** (every command): `0` fine, `1` problems found (`check`, `scan`,
`audit --strict`), `2` could not run (bad input, bad option, unwritable
output; never a traceback), `141` the output pipe was closed (`| head`),
`130` interrupted. An unexpected crash is also `2`, so CI never reads a bug
in redbg as "your agent broke a rule"; `REDBG_DEBUG=1` shows the traceback.

## Quickstart

**1. Record.** Wrap your tool-calling loop with `Recorder`:

```python
from redbg import Recorder

with Recorder("session.jsonl", agent="my-agent") as rec:
    rec.prompt("user", "Summarize main.py")
    call = rec.tool_call("read_file", {"path": "main.py"})
    try:
        text = open("main.py").read()
    except OSError as exc:
        rec.tool_result(call, ok=False, error=str(exc))
    else:
        rec.tool_result(call, ok=True, output=text)
    rec.response("main.py prints hello.")
```

Record token counts with `rec.usage(input_tokens, output_tokens, ...)` after
each model call (Claude Code transcripts carry them already, counted once per
message); `redbg info` prints the totals and `redbg check --max-tokens N`
gates on them. redbg counts tokens, it does not price them.

Or decorate tool functions — calls and results are recorded automatically,
exceptions become failed results. `async def` tools and objects with an
`async def __call__` work too (the awaited value is recorded, and concurrent
`asyncio.gather` calls pair correctly). Generator functions (sync or async)
are rejected with a clear `TypeError` — a wrapper only sees the generator
object, so wrap the code that consumes it instead:

```python
with Recorder("session.jsonl") as rec:
    @rec.wrap
    def read_file(path): ...

    @rec.wrap
    async def fetch(url): ...
```

**2. Replay.** Step through like a debugger:

```bash
$ redbg replay session.jsonl
(redbg –/4) n        # step into the first tool call
(redbg 1/4) s        # show full details: args, output, duration, context
(redbg 1/4) /main.py # search tool/args/output
(redbg 1/4) t        # timing table for all steps
(redbg 1/4) q
```

Non-interactive: `--list`, `--show N`, `--cmd "n;n;s"`, `--export-md report.md`.

`Recorder(path)` creates the file fresh: recording to a path that exists
replaces the old trace, so give each run its own file name.

**3. Diff.** Find where two runs diverged:

```bash
$ redbg diff monday.jsonl tuesday.jsonl
```

Aligns the step streams (`difflib.SequenceMatcher` sequence alignment),
headlines the first
divergence, prints a side-by-side table (`=` same, `~` args changed,
`!` tool changed, `≠` status changed, `+`/`-` added/removed), then a
field-level diff at the divergence point.

**4. Fork.** Re-run the tail of a session with modified input:

```bash
$ redbg fork tuesday.jsonl --at 3 \
    --override-args '{"path": "main.py"}' \
    --tools my_tools.py \
    --save fork.jsonl
```

`my_tools.py` defines `TOOLS = {"read_file": callable, ...}` (and
optionally `MODEL` for live mode). Two strategies:

- `playback` (default): recorded model responses are replayed verbatim;
  tool calls are **re-executed** against your implementations. Deterministic
  and free — answers "with this different input, does my loop logic still
  behave?"
- `live`: your `MODEL(messages)` is actually called each turn. Answers
  "what would the model do now?" — non-deterministic, may cost money.

Every forked trace carries provenance (`forked_from`, `at_step`,
`strategy`) so a fork is never mistaken for an original recording.

**5. Check (CI gate).** Fail the build when a run regresses or breaks a
rule. Exit codes: `0` pass, `1` violations, `2` could not run.

```bash
redbg check run.jsonl --baseline golden.jsonl \
    --ignore-keys request_id,timestamp \
    --fail-on tool_changed,status_changed,removed \
    --max-steps 40 --max-failures 0 --max-repeats 3 \
    --forbid-tool 'delete_*' --forbid-tool shell \
    --require-tool write_report
```

| rule | fails when |
|---|---|
| *(always, unless `--allow-incomplete`)* | the session has no `session_end`, ended with status `error`, or a step has no result |
| *(always, unless `--allow-empty`)* | the trace has zero tool steps (empty, garbage, or crashed before the first call), or no rule was evaluated at all — a broken recorder must not pass CI |
| `--baseline FILE` | the aligned diff vs the baseline contains a kind in `--fail-on` (default: every change — `args_changed`, `tool_changed`, `status_changed`, `added`, `removed`; `output_changed` is opt-in because outputs often vary) |
| `--max-steps N` / `--max-failures N` | more than N steps / failed steps |
| `--max-repeats N` | a tool is called more than N times **in a row with identical args** — the usual shape of a stuck loop |
| `--max-cycles N` | an alternating pattern of 2-8 calls (`Read, Edit, Read, Edit, ...`) repeats more than N times (same args each time; `--ignore-keys` for ids) |
| `--forbid-tool GLOB` / `--require-tool GLOB` | a call matches / no call matches (shell globs, matched case-insensitively after Unicode NFKC normalization with zero-width/bidi characters removed — so `Delete_File` and full-width `ｄelete_file` both match `delete_*`). Namespaced names are also tried without their prefix, so `delete_*` catches `mcp__files__Delete_File` and `files/delete_file` |
| `--forbid-path GLOB` / `--forbid-write GLOB` | a step reads, writes or deletes a matching file (`--forbid-write` ignores reads). Uses the same file ledger as `redbg files`: declared for edit tools, inferred for shell commands (including Windows paths, `$HOME/.env`). `~/` in a glob matches any home. Windows drive paths compare case-insensitively |
| `--forbid-arg REGEX` | a call's tool name or any argument string matches (case-insensitive, after the same normalization): `'rm\s+-rf'`, `'git push.*--force'`. The backstop for what the ledger cannot see |
| `--max-tokens N` | the session used more than N tokens (input + output + cache read + cache creation: counts, not cost). Fails if the trace has no usage data |

`--json` prints a machine-readable result; options taking lists accept
commas or repetition (`--forbid-arg` takes one regex per flag). In GitHub
Actions, `--github` turns each violation into an `::error` annotation (text
from the trace is made printable and escaped, so a tool name cannot forge
another workflow command) and `--junit report.xml` writes one test case per
rule for any CI that reads JUnit:

```yaml
- run: pip install redbg
- run: python run_agent_eval.py --trace run.jsonl   # your harness, records with Recorder
- run: redbg check run.jsonl --baseline tests/golden.jsonl --max-repeats 3 --max-cycles 3
        --forbid-write '.env' --forbid-arg 'git push.*--force' --github --junit redbg.xml
```

From Python: `run_check(Session.load("run.jsonl"), CheckRules(max_repeats=3),
baseline=Session.load("golden.jsonl")).passed`.

## More commands

```bash
redbg info session.jsonl            # summary: steps, failures, tool time, loops
redbg diff a.jsonl b.jsonl --json   # machine-readable diff
redbg diff a.jsonl b.jsonl --ignore-keys request_id   # ignore noisy args
redbg scan session.jsonl            # audit for likely secrets (exit 1 if found)
redbg redact raw.jsonl -o clean.jsonl   # strip secrets before sharing
redbg import otel.json -o out.jsonl     # convert OTel/Langfuse-shaped traces
```

`redbg` reads `.jsonl.gz` transparently everywhere a trace is accepted, and
`-` means standard input (`curl ... | redbg info -`; one input per command).
UTF-8 BOM and UTF-16/32 files (what PowerShell's `>` writes) open directly.
Token counts show up in `info` when the trace has them (below).

## Reports for other tools, and evidence

```bash
redbg check run.jsonl --baseline good.jsonl --sarif redbg.sarif   # code-scanning dashboards
redbg audit run.jsonl --sarif audit.sarif
redbg otel  run.jsonl -o run.otlp.json       # OpenTelemetry (OTLP/JSON) spans; sends nothing
redbg digest run.jsonl                       # SHA-256 + timeline anomalies
redbg digest run.jsonl --expect <sha256>     # exit 1 if the file is not the one you saved
```

- **SARIF 2.1.0** (`check`, `audit`): one result per violation or finding
  (`audit`: high = error, medium = warning, low = note). A trace has no source
  lines, so a result points at the trace file and names the step
  (`logicalLocations`, `properties.step`). Three generated documents were
  checked against the published SARIF 2.1.0 JSON schema; whether GitHub's
  upload step accepts a result without a line number was not tried.
- **`otel`** writes an OTLP/JSON `resourceSpans` document: one root span per
  session and one child span per tool step (error status for failed steps).
  Ids are derived from the session id, so exporting twice gives identical
  bytes. Tool arguments are **left out** unless you pass `--with-args`, and
  are then redacted first. Nothing is sent to any server; load the file with
  whatever reads OTLP/JSON (for example an OpenTelemetry Collector). Attribute
  names are `redbg.*`; no OpenTelemetry semantic-convention names are claimed.
- **`digest`** prints the SHA-256 of the file exactly as stored (a `.gz` file
  hashes its compressed bytes), the event/step counts, and anomalies that
  suggest a spliced or damaged file: duplicate event ids, timestamps going
  backwards, tool calls with no result. A damaged file still gets its hash
  (exit 2). It detects accidents and crude edits; it is **not** tamper-proof,
  since anyone who can edit the file can edit the hash you stored beside it.

## Sharing a transcript safely

```bash
redbg scan    raw.jsonl --pii --paths --also "Acme Corp"      # what would be removed?
redbg redact  raw.jsonl -o shareable.jsonl --pii --paths --also "Acme Corp"
redbg scan    shareable.jsonl --pii --paths --also "Acme Corp"   # must say clean
```

Works on Claude Code and Codex transcripts as well as redbg traces (the
output keeps the input's format). Beyond secrets, three opt-in layers:
`--pii` (e-mail, IPv4 and Luhn-valid card numbers; a dotted version number such
as `1.2.3.4` looks like an IP and is redacted too), `--paths` (the user-name
part of `/home/NAME`, `/Users/NAME`, `C:\Users\NAME`; the rest of the path
stays so diffs still line up) and `--also WORD` (your name, company or host
names, case-insensitive, repeatable). Not covered: names in free prose you did
not list, JSON key names, phone numbers, street addresses. `--redact` on other
commands, `--export-html` and `import --redact` apply the secret rules only.

## Python API

```python
from redbg import Session, Navigator, render_diff, ForkSpec, fork_session

a, b = Session.load("monday.jsonl"), Session.load("tuesday.jsonl")
print(render_diff(a, b, use_color=False))

nav = Navigator(a)
nav.next(); nav.prev(); nav.goto(3)

spec = ForkSpec(at_step=3, strategy="playback",
                override_args={"path": "main.py"},
                tool_impls={"read_file": lambda args: open(args["path"]).read()})
forked = fork_session(b, spec)
forked.save("fork.jsonl")
```

## Trace format

One JSON object per line (JSONL), append-only, stream-written — a crashed
run still leaves a usable partial trace. Event types: `session_start`,
`prompt`, `response`, `tool_call`, `tool_result`, `note`, `session_end`.
A *step* is one `tool_call`/`tool_result` pair. Unknown event types are
preserved on load (a newer recorder's trace still opens) but ignored by the
step engine. See `examples/sample-a.jsonl`.

## Reading other tools' logs

| format | detected by | notes |
|---|---|---|
| Claude Code transcripts | `sessionId` / `uuid` lines | tool_use/tool_result paired by id; real timestamps give real durations; subagent (sidechain) steps are flagged; thinking blocks, attachments and queue lines are skipped and counted |
| Codex CLI rollouts | `response_item` + `payload` | `function_call`, `local_shell_call`, `apply_patch` and their outputs; the exit code inside the output envelope sets ok/failed |
| OpenAI / Anthropic message logs | `role` + `tool_calls` / content blocks | JSON array, `{"messages": [...]}`, or JSONL |
| OTel / Langfuse exports | `spans` / `observations` | heuristic and lossy (below) |

The field mappings come from the logs as we have seen them and vendors change
them without notice: unknown line or block types are counted in a note
(`redbg info` shows it), never fatal. A cut-off final line (writer killed
mid-write) is reported and the session ends with status `truncated`, so
`redbg check` fails closed on it. Tool outputs over 20,000 characters are
cut with their SHA-256 kept (diffs still see changes). Formats were verified
against real Claude Code transcripts; the Codex and message-array mappings
follow the documented shapes and are covered by synthetic fixtures only.
`redbg import SRC -o OUT.jsonl [--redact]` writes the converted native trace.

## Importing OTel traces

`redbg import` converts OTel-shaped spans and Langfuse-shaped observations
(`{"observations": [...]}` / `{"spans": [...]}` / `{"traces": [...]}`) into
redbg format. It is heuristic and lossy by design — spans whose names
mention tools become tool steps, generation spans become responses,
everything else becomes notes. Always verify with `redbg info` afterward.

## Secrets and safety

The recorder redacts by default (and `redbg redact` applies the same rules
to an existing trace):

- **By key name** — the whole value under a structured (dict) key matching
  `api_key|secret|token|password|auth…|bearer|credential|private_key|ssn|card_number|...`
  in args, results and metadata.
- **By shape, anywhere inside a string** — OpenAI (`sk-…`, `sk-proj-…`,
  `sk-svcacct-…`), Anthropic (`sk-ant-…`), GitHub (`ghp_/gho_/ghu_/ghs_/ghr_…`,
  `github_pat_…`), Slack tokens and webhooks, Stripe (`sk_live_…`,
  `rk_test_…`), AWS key ids (`AKIA…`), Google (`AIza…`), Hugging Face
  (`hf_…`), JWTs, and **the whole PEM private-key block** (header, body and
  footer; an unterminated block is redacted to the end of the string).
- **Free-text credentials** — `Bearer …` values (any spacing, `Bearer:`
  too; 8+ chars containing a digit, so prose like "the bearer of…"
  survives), `Basic …` values (base64 with a digit, `+`, `/` or `=`),
  `user:password@` in URLs, and `KEY=value` / `KEY: value` assignments
  (value 4+ chars) whose key name contains `api_key`/`apikey`, `secret`,
  `token`, `password`/`passwd`, `pwd`, `credential`, `private_key`,
  `access_key` or `session_key` — which covers
  `.env` / `export` lines, YAML/HTTP-header style lines, JSON-in-text and
  query strings like `?api_key=…&`. The key name is kept
  (`OPENAI_API_KEY=[REDACTED]`) so the trace stays readable.
- **More shapes** — npm, GitLab, SendGrid, Stripe webhook secrets, Google
  OAuth, Slack app tokens, PyPI, Shopify, DigitalOcean, Docker Hub, Linear,
  Azure `AccountKey=` / SAS `sig=`, Sentry DSN keys, `Cookie:` /
  `Set-Cookie:` values, `Authorization: <scheme> value`, `curl -u user:pass`
  and `mysql -pSECRET`.
- **Personal data, opt-in** — `redbg scan --pii` / `redbg redact --pii` also
  flag e-mail addresses, IPv4 addresses and card numbers that pass the Luhn
  check; `--paths` and `--also` are described under "Sharing a transcript
  safely". Off by default (addresses are everywhere in normal prose). Phone
  numbers, street addresses and names you did not list are not detected.

Kept on purpose, so cost and usage stay debuggable: numeric (or
digit-only string) LLM usage counters such as `max_tokens`,
`prompt_tokens`, `totalTokenCount` and `token_count`, the
`*_tokens_details` dicts (each field inside is still checked), and keys
like `author`. A count key that also names a secret (`secret_tokens`,
`access_token_count`) is still redacted. Values nested more than 100 levels
deep are redacted rather than inspected.

**Limits:** this is pattern matching — a safety net, not a guarantee. It
will miss secrets with no recognizable shape or key name (a bare
password on its own line, a custom token format) and can occasionally
redact a harmless `token: value`-shaped line. Always run `redbg scan`
before sharing a trace; it checks the same rules.

Traces are treated as untrusted input: control characters (ANSI/OSC
escapes, `\r`) and invisible/format characters (bidi overrides such as
U+202E, zero-width characters, U+2028/2029) in tool names, args and
outputs are shown escaped (`\x1b[2J`, `\u202e`), so a crafted trace cannot
drive your terminal or disguise one tool name as another. Markdown
reports fence content so it cannot inject headings/HTML. `redact`,
`import` and `fork --save` refuse to overwrite their own input file.
Pathologically nested traces exit with code 2 instead of crashing.
`fork --tools FILE` *executes* that Python file — only point it at code
you trust.

Tool outputs are truncated
at 20,000 chars (configurable via `max_output_chars`) with a SHA-256 of the
full output retained so diffs still detect changes. Run `redbg scan`
before sharing any trace, and `redbg redact` to clean one.

## Windows

Written to be portable: no shell calls, no signals, no POSIX-only modules in
the package; files are written with `\n` line endings and read in any of
UTF-8/UTF-16/UTF-32 or CRLF; `os.replace` onto a file another program has
open is retried briefly; a console or redirect that cannot show a character
(cp1252, ASCII) prints it as `\uXXXX` instead of crashing; colors are used
only when the console accepts them. **Nobody has run it on Windows** (the
test suite and a static review were done on Linux): if something breaks
there, open an issue. `bench/bench.py` is POSIX-only.

## Limitations (honest)

- **Playback forks don't model the model.** Replaying recorded model text
  with different tool inputs shows you what your *loop logic* does, not what
  the *LLM* would have said. Use `live` for true what-if on model behavior —
  and accept that live forks are non-deterministic experiments, not
  reproductions.
- **No framework auto-instrumentation.** redbg won't monkeypatch LangChain,
  AutoGen, or the Claude Agent SDK — explicit `Recorder` hooks only.
  Adapters are a documented v2 extension point, not a v1 feature.
- **Diff aligns sequences; it doesn't understand intent.** Reordered steps
  surface as deletions + insertions (never a fabricated "moved"). Args are
  canonicalized (key order ignored, `1.0` == `1`, `--ignore-keys` drops
  noisy fields), but semantically equal values with different text
  (`"1"` vs `1`, reworded strings) still count as changed.
- **Loop detection needs identical calls.** `--max-repeats` sees one call
  repeated back-to-back; `--max-cycles` / `audit` see alternating patterns of
  2-8 calls. Both compare tool and exact arguments, so a loop whose arguments
  change each time (a counter, a timestamp, a slightly reworded query) is
  invisible until you pass `--ignore-keys`; `--max-steps` is the backstop.
- **Single-agent sessions.** Multi-agent / swarm traces (parallel tool calls
  across agents) load, but the step engine treats them as one flat sequence
  (Claude Code subagent steps are flagged `sidechain` but still interleaved).
- **`why` is evidence, not proof.** It cannot see the model's reasoning
  (thinking blocks are not read), outputs cut at 20,000 characters can hide
  an origin, and a value that only *resembles* an earlier one is not linked.
  "Not found" means "not found in the stored text".
- **File effects are partial for shell.** Edit/Write/apply_patch name their
  files (declared). For Bash/shell, redbg parses redirects, `tee`, `sed -i`,
  `rm`, `mv`, `cp`, `touch` (inferred, marked `*`); anything a script writes
  internally is invisible. `files`/`blame` show what is *known*, not a
  complete audit.
- **`audit` and `--forbid-path` are heuristics over text.** `invented_path`
  means "not found in what redbg stored", which also happens when an output was
  cut at 20,000 characters or the agent learned the path from something redbg
  does not record. Paths are inferred from shell commands by pattern: a
  script, a `make` target, a variable or a sub-shell can touch files without
  appearing (`$HOME/x` and `$(pwd)/x` forms are kept as written, never
  resolved). POSIX-style paths compare case-sensitively (a `.ENV` on a
  case-insensitive file system slips past `--forbid-path .env`; Windows drive
  paths are compared case-insensitively). Use `--forbid-arg` as a second net, and never treat an empty
  `audit` as a clean bill of health.
- **Token counts need data.** Only Claude Code transcripts and
  `Recorder.usage()` provide them; Codex and message-array logs do not (their
  usage fields are not read), so `--max-tokens` fails closed on those.
- **Breakpoint regexes are yours.** `break ~REGEX` runs your pattern over
  every step; a pathological pattern is slow.
- **Timestamps are wall-clock.** Cross-machine comparison of durations is
  approximate; `mono` deltas are only meaningful within one recording host.
- **Import is lossy.** Anything the heuristics don't recognize becomes a
  `note` — check the result before trusting a diff built on imported data.

## How it compares

Only statements we could check against each project's own page are listed.

| | redbg | [rewind](https://pypi.org/project/rewind-agent/) (`rewind-agent` 0.17.1) | [LangGraph time travel](https://docs.langchain.com/oss/python/langgraph/use-time-travel) | [AgentOps](https://microsoft.github.io/autogen/0.2/docs/ecosystem/agentops) | [Langfuse](https://langfuse.com) (self-host) | [llmvcr](https://pypi.org/project/llmvcr/) |
|---|---|---|---|---|---|---|
| Runs fully local, no account | yes | yes (records under `~/.rewind`) | yes | no — API key + hosted dashboard | yes, but needs Postgres, ClickHouse, Redis and S3 ([source](https://blog.elest.io/self-host-langfuse-to-trace-your-ai-agents/)) | yes |
| Install footprint | pure Python, 0 deps | pip SDK that downloads a native binary on first use | part of LangGraph | SDK + cloud | multi-service stack | SDK + provider extras |
| Framework-agnostic | yes (explicit hooks) | proxy or wrappers | LangGraph only | integrations | SDKs/OTel | provider SDKs |
| Step diff of two runs | yes, sequence-aligned + first divergence | yes | — | — | — | — |
| Fork from a step | yes (playback or live) | yes (cached replay) | yes (checkpoints) | yes ("time travel") | — | — |
| CI regression gate | `redbg check` (exit codes, GitHub annotations, JUnit) | yes: Python `Assertions` vs a baseline (steps, models, tool calls, errors, token usage with tolerance); GitHub Action not re-verified | — | — | — | replay tests |
| Policy rules on tools / files / commands / token budget | yes | not on its PyPI page |
| SARIF / OpenTelemetry export, secret redaction | yes (`--sarif`, `otel`, `redact`) | not on its PyPI page | — | — | — | — |
| Loop detection | identical calls, back-to-back or alternating (2-8 call cycles) | — | — | "recursive thought detection" | — | — |
| Auto-instrumentation | **no** | yes (OpenAI Agents SDK, Pydantic AI) | built in | unverified | unverified | yes (patches provider SDKs) |
| Web UI | **no** | not on its PyPI page (earlier read: yes) | unverified | yes (hosted dashboard) | yes | no (CLI) |

"—" means the page we checked didn't mention it, not that it can't be done.
The rewind column was re-read this round from its PyPI page only (its
repository link was not reachable from our build environment); the page
still says 0.17.1 and that the native binary downloads on first use. The
[claude-code-log](https://pypi.org/project/claude-code-log/) PyPI page (1.7.0)
adds a terminal UI and per-session cost questions to its HTML export; redbg
counts tokens but does not price them. Its PyPI metadata (read
2026-11-07) requires Python 3.10+ and installs click, dateparser, gitpython,
jinja2, pydantic and others; redbg needs Python 3.9+ and nothing else.
The 2026-11-08 re-read of the rewind and claude-code-log PyPI descriptions found
no mention of SARIF, OpenTelemetry, redaction or hashing (descriptions only,
not their repositories). Where redbg is weaker: no auto-instrumentation, no web UI, no LLM-judge
scoring (rewind's earlier-read repo listed these; not re-checked). Where it aims to be stronger: nothing to run
or sign up for, a plain JSONL format you can grep, and a diff that tells
you the *first* step that diverged.

### Opening big Claude Code transcripts (measured)

Same machine, run by us; re-run redbg's side with `python bench/bench.py` (`bench/RESULTS.md` also times `audit` and a `check` of a run against itself)
(inputs are generated, no real data; numbers vary run to run, 2x on a busy
host). Peak memory is the process's maximum resident size.

| | what it does | 100 MB synthetic transcript | 7 MB real transcript |
|---|---|---|---|
| **redbg 0.3** | interactive debugger | first step on screen in **0.07-0.10 s** on a quiet host (0.25-0.40 s when the host's load average was ~10); full load 1.4 s quiet / 3.3 s loaded, 108 MB (re-measured in round 4 at load ~9: 0.27-0.44 s and 1.9-3.1 s, same memory; indistinguishable from the previous commit run side by side, see `bench/RESULTS.md`; round 5 at load 9-11: 0.28-0.57 s and 2.8-3.4 s, memory unchanged, and a side-by-side run on 25 MB inputs showed no consistent change) | first step 0.07 s, 19 MB |
| redbg 0.2 (before) | interactive debugger | cannot open (rejects the format) | cannot open |
| [claude-code-transcripts](https://pypi.org/project/claude-code-transcripts/) 0.6 (`json`) | static HTML pages | 6.2 s, 267 MB, writes 88 MB of HTML | 0.4 s, 49 MB |
| [claude-code-log](https://pypi.org/project/claude-code-log/) 1.7.0 | static HTML/Markdown | not run: its strict validation rejected our synthetic attachment lines | 1.7 s, 94 MB |

The two viewers are converters (read the result in a browser); neither
steps, diffs, breaks, explains or gates CI, so the table compares only
"time until you can see something". Commercial trace UIs
([Langfuse](https://langfuse.com), [LangSmith](https://docs.smith.langchain.com),
[Arize Phoenix](https://github.com/Arize-ai/phoenix),
[AgentOps](https://www.agentops.ai)) need SDK instrumentation and a
server or account; we did not benchmark them and make no speed claim.

## Roadmap (v2, not promised)

Framework adapters · full TUI · SQLite export for ad-hoc queries · remote
trace ingestion · multi-agent step views.
