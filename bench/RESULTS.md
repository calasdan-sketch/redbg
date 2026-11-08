# Benchmark (100 MB inputs)

Python 3.13.18 on Linux x86_64; best of 3 for time-to-first-view, single run for load. Re-run: `python bench/bench.py`.

Host load average (1/5/15 min) at the end of the run: 11.2/12.0/11.2. Absolute times scale with it; compare rows within one table. Round 5 run (baseline = round 4 commit d075e74): the `current` rows ran first and the baseline second, so a one-sided gap is not evidence; see docs/ROUND5.md for the interleaved comparison.

| version | input | file MB | steps | full load | peak memory | time to first view | `why` (mid-step) | `audit` | `check` vs itself | `otel` | `digest` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| current | redbg native | 105 | 26643 | 2.17 s | 195 MB | 0.36 s | 4.19 s | 106.94 s | 10.35 s | 5.18 s | 4.33 s |
| current | Claude Code | 105 | 14947 | 5.22 s | 108 MB | 0.44 s | 5.61 s | 57.70 s | 10.88 s | 5.58 s | 5.22 s |
| d075e74 | redbg native | 105 | 26643 | 2.24 s | 195 MB | 0.27 s | 3.35 s | 105.48 s | 9.08 s | - | - |
| d075e74 | Claude Code | 105 | 14947 | 4.15 s | 108 MB | 0.25 s | 3.19 s | 44.59 s | 8.79 s | - | - |
