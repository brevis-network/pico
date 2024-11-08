# Performance Comparison Script for Git Branches

## Objective

The goal of this script is to compare the performance differences between the `main` branch and the `current` branch within the same environment. The script can be customized for different configurations and workloads.

## Configuration

```bash
# Python settings
PYTHON_CMD="/usr/bin/python3"
REQUIRED_PYTHON_DEPENDENCIES=("pandas" "collections" "json" "matplotlib" "numpy")

# Rust settings
EXAMPLE_NAME="test_riscv_machine"
RUST_LOG="info"
RUSTFLAGS="-Awarnings"
FRI_QUERIES="1" 
CMD_ARGS="f 40" # Workload

# Comparison settings
SKIP_BASE_RUN=true # Important FLAG that determines the script's execution mode.
LOG_PREFIX_0="main_${EXAMPLE_NAME}_${CMD_ARGS// /_}" # Main branch
LOG_PREFIX_1="new_${EXAMPLE_NAME}_${CMD_ARGS// /_}" # Current branch
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
BASE_BRANCH="main"
```


## Script Behavior

### When the `main` branch performance log already exists:

If the performance log for the `main` branch (e.g., `test_${LOG_PREFIX_0}.log`) already exists, set `SKIP_BASE_RUN=true` to prevent running the benchmark on the `main` branch. The script will perform the following steps:

1. Run the workload on the current branch and save the output in `test_${LOG_PREFIX_1}.log`.
   ```bash
   RUST_CMD="RUST_LOG=$RUST_LOG RUSTFLAGS=$RUSTFLAGS FRI_QUERIES=$FRI_QUERIES cargo run --release --example $EXAMPLE_NAME $CMD_ARGS"
   eval "$RUST_CMD"
   ```
2. Run `analyze.py` with `test_${LOG_PREFIX_0}.log` and `test_${LOG_PREFIX_1}.log` as input to generate performance comparison results.

### When the `main` branch performance log does not exist:

If the `main` branch log does not exist, follow these steps:

1. Modify the configuration in `branch_log_analysis` (set `SKIP_BASE_RUN=false`).
2. Commit changes to ensure a clean Git working tree.
3. Run the script to compare the performance between branches.

The script will perform the following steps:

1. Check Git status.
2. Switch to the `main` branch with `git checkout main`.
3. Run the workload on the `main` branch and save the output to `test_${LOG_PREFIX_0}.log`.
4. Switch back to the original branch (your dev branch) using `git checkout -`.
5. Run the workload on your dev branch and save the output to `test_${LOG_PREFIX_1}.log`.
6. Run `analyze.py` with both log files as input and generate the comparison results.

**Note:**
In this case, the script requires an additional git commit task because it uses git checkout to obtain the performance of the main branch in the current environment. The script will check the working tree is clean for a safe git checkout.
If comparing different workloads (e.g., `fibo 50`, `fibo 100`, etc.) and there is no `main` branch log for those workloads, multiple commits or amendments will be required to safely obtain performance results for each workload from the `main` branch.


### Path Handling

1. **Recommendation: Run the script from the project root directory:**
   It is recommended to execute the script from the root directory of the project, e.g.:
   ```bash
   ./tools/scripts/branch_perf_comparison.sh
   ```

2. **Avoid Running the Script in Git Submodules:**
   The script should not be executed from a Git submodule, while the current project does not use submodules.

3. **Do Not Run from Branch-Specific Subdirectories:**
   When comparing performance across two branches, **do not run the script from a directory that is specific to only one of the branches**. 

