# redbg — gdb for agent sessions

**Find the exact step where your agent went wrong — and fail CI when it
happens again.** Local files, no account, no server, zero dependencies.

Record tool-calling agent sessions, then debug them like a program:
**step** forward/back through tool calls, **inspect** the exact
prompt/response at each step, **diff** two runs to find where they
diverged, **fork** a session at any step to explore what-if
scenarios, and **check** a run against a known-good baseline in CI.

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

## Install

```bash
pip install redbg
```

Python 3.9+. No runtime dependencies — it installs anywhere.

**Try it in 30 seconds** (from a clone of this repo; uses the two sample
traces in `examples/`):

```bash
redbg diff  examples/sample-a.jsonl examples/sample-b.jsonl
redbg check examples/sample-b.jsonl --baseline examples/sample-a.jsonl; echo "exit=$?"
```

```
✗ check FAILED: examples/sample-b.jsonl vs baseline examples/sample-a.jsonl
  [divergence] First divergence at A:— / B:1: step added in B ('read_file')
  [added] baseline:— / candidate:1 'read_file': added
  rules: complete, baseline
exit=1
```

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
| `--forbid-tool GLOB` / `--require-tool GLOB` | a call matches / no call matches (shell globs, matched case-insensitively after Unicode NFKC normalization with zero-width/bidi characters removed — so `Delete_File` and full-width `ｄelete_file` both match `delete_*`) |

`--json` prints a machine-readable result; options taking lists accept
commas or repetition. In GitHub Actions:

```yaml
- run: pip install redbg
- run: python run_agent_eval.py --trace run.jsonl   # your harness, records with Recorder
- run: redbg check run.jsonl --baseline tests/golden.jsonl --max-repeats 3
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

`redbg` reads `.jsonl.gz` transparently everywhere a trace is accepted.

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

## Importing existing traces

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
- **The loop detector only sees back-to-back repeats.** Alternating
  cycles (`a, b, a, b, …`) aren't flagged by `--max-repeats`; use
  `--max-steps` as a backstop.
- **Single-agent sessions.** Multi-agent / swarm traces (parallel tool calls
  across agents) load, but the step engine treats them as one flat sequence.
- **Timestamps are wall-clock.** Cross-machine comparison of durations is
  approximate; `mono` deltas are only meaningful within one recording host.
- **Import is lossy.** Anything the heuristics don't recognize becomes a
  `note` — check the result before trusting a diff built on imported data.

## How it compares

Only statements we could check against each project's own page are listed.

| | redbg | [rewind](https://github.com/risjai/rewind) | [LangGraph time travel](https://docs.langchain.com/oss/python/langgraph/use-time-travel) | [AgentOps](https://microsoft.github.io/autogen/0.2/docs/ecosystem/agentops) | [Langfuse](https://langfuse.com) (self-host) | [llmvcr](https://pypi.org/project/llmvcr/) |
|---|---|---|---|---|---|---|
| Runs fully local, no account | yes | yes | yes | no — API key + hosted dashboard | yes, but needs Postgres, ClickHouse, Redis and S3 ([source](https://blog.elest.io/self-host-langfuse-to-trace-your-ai-agents/)) | yes |
| Install footprint | pure Python, 0 deps | Rust binary / pip SDK | part of LangGraph | SDK + cloud | multi-service stack | SDK + provider extras |
| Framework-agnostic | yes (explicit hooks) | proxy or wrappers | LangGraph only | integrations | SDKs/OTel | provider SDKs |
| Step diff of two runs | yes, sequence-aligned + first divergence | yes | — | — | — | — |
| Fork from a step | yes (playback or live) | yes (cached replay) | yes (checkpoints) | yes ("time travel") | — | — |
| CI regression gate | `redbg check` | yes (baseline + GitHub Action) | — | — | — | replay tests |
| Loop detection | consecutive identical calls | — | — | "recursive thought detection" | — | — |
| Auto-instrumentation | **no** | yes (OpenAI Agents SDK, Pydantic AI) | built in | unverified | unverified | yes (patches provider SDKs) |
| Web UI | **no** | yes | unverified | yes (hosted dashboard) | yes | no (CLI) |

"—" means the page we checked didn't mention it, not that it can't be done.
Where redbg is weaker: no auto-instrumentation, no web UI, no LLM-judge
scoring (rewind has these). Where it aims to be stronger: nothing to run
or sign up for, a plain JSONL format you can grep, and a diff that tells
you the *first* step that diverged.

## Roadmap (v2, not promised)

Framework adapters · full TUI · SQLite export for ad-hoc queries · remote
trace ingestion · multi-agent step views.
