# Benchmark (100 MB inputs)

Python 3.13.18 on Linux x86_64; best of 3 for time-to-first-view, single run for load. Re-run: `python bench/bench.py`.

Host load average (1/5/15 min) at the end of the run: 10.7/11.2/11.1. Absolute times scale with it; compare rows within one table.

| version | input | file MB | steps | full load | peak memory | time to first view | `why` (mid-step) | `audit` | `check` vs itself |
|---|---|---|---|---|---|---|---|---|---|
| current | redbg native | 105 | 26643 | 2.66 s | 195 MB | 0.40 s | 2.93 s | 95.23 s | 6.82 s |
| current | Claude Code | 105 | 14947 | 3.28 s | 108 MB | 0.25 s | 4.25 s | 55.99 s | 9.65 s |
| b7d5254 | redbg native | 105 | 26643 | 2.21 s | 194 MB | 2.58 s | - | - | - |
| b7d5254 | Claude Code | 105 | 14947 | cannot open | - | cannot open | - | - | - |

Notes: `audit` includes the credential scan, which is most of its time
(`audit --no-secrets` is several times faster). `check` is run against itself
(`--baseline` = the same file, `--max-cycles 99`), the common CI case of an
almost identical run; before round 3 that alignment alone took about half a
minute on the native input on this host. The previous quiet-host run
(load average ~1) measured full load 0.94 s / 1.41 s and time to first view
0.10 s / 0.07 s for the same inputs.
