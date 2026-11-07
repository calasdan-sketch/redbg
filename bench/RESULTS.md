# Benchmark (100 MB inputs)

Python 3.13.18 on Linux x86_64; best of 3 for time-to-first-view, single run for load. Re-run: `python bench/bench.py`.

| version | input | file MB | steps | full load | peak memory | time to first view | `why` (mid-step) |
|---|---|---|---|---|---|---|---|
| current | redbg native | 105 | 26643 | 0.94 s | 195 MB | 0.10 s | 1.30 s |
| current | Claude Code | 105 | 14947 | 1.41 s | 107 MB | 0.07 s | 2.16 s |
| b7d5254 | redbg native | 105 | 26643 | 0.65 s | 194 MB | 0.66 s | - |
| b7d5254 | Claude Code | 105 | 14947 | cannot open | - | cannot open | - |
