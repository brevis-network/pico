## Prerequisites

Logs should be put in `./logs/` and named `test_{}.log`. The main analysis function lies in `analyze.py`. 

## Workflow
Assume we have two logs `test_a.log` and `test_b.log` in `./logs/`. By specifying prefixes `a` and `b` in `analyze.py`, we can compare the two logs in the following workflow:
1. Parse `test_a.log` and `test_b.log` into `perf_a.csv` and `perf_b.csv` respectively.
2. Analyze each logs and plot performance analysis in `./a/` and `./b/` respectively.
3. Compare the two logs and plot performance comparison in `./log_a-log_b/`.


