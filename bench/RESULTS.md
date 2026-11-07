# Benchmark (100 MB inputs)

Python 3.13.18 on Linux x86_64; best of 3 for time-to-first-view, single run for load. Re-run: `python bench/bench.py`.

Host load average (1/5/15 min) at the end of the run: 8.9/10.6/10.7. Absolute times scale with it; compare rows within one table.

| version | input | file MB | steps | full load | peak memory | time to first view | `why` (mid-step) | `audit` | `check` vs itself |
|---|---|---|---|---|---|---|---|---|---|
| current | redbg native | 105 | 26643 | 1.94 s | 195 MB | 0.27 s | 1.83 s | 62.61 s | 5.94 s |
| current | Claude Code | 105 | 14947 | 3.14 s | 108 MB | 0.44 s | 4.38 s | 45.27 s | 5.86 s |
| 6f8ad30 | redbg native | 105 | 26643 | 1.21 s | 195 MB | 0.12 s | 3.16 s | 79.25 s | 7.08 s |
| 6f8ad30 | Claude Code | 105 | 14947 | 3.81 s | 108 MB | 0.41 s | 4.51 s | 34.61 s | 4.17 s |
