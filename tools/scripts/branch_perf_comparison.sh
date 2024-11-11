#!/bin/bash

# Path settings
ORIGINAL_DIR=$(pwd)
ROOT_DIR=$(git rev-parse --show-toplevel)
LOG_DIR="$ROOT_DIR/tools/log_analysis/logs"
ANALYZE_SCRIPT="$ROOT_DIR/tools/log_analysis/analyze.py"

# Python settings
PYTHON_CMD="/usr/bin/python3"
REQUIRED_PYTHON_DEPENDENCIES=("pandas" "collections" "json" "matplotlib" "numpy")

# User-defined Rust commands as an array (multiple commands for batch execution)
RUST_CMD_ARRAY=(
    "FRI_QUERIES=1 cargo run --release --example test_riscv_machine"
    "/usr/bin/time -v env RUST_LOG=info FRI_QUERIES=1 cargo run --release --example test_riscv_machine"
)

# Log prefixes for the main and current branch (multiple prefixes for batch processing)
LOG_PREFIX_0_ARRAY=("main_test_riscv_machine_0" "main_test_riscv_machine_1")
LOG_PREFIX_1_ARRAY=("new_test_riscv_machine_0" "new_test_riscv_machine_1")

# Comparison settings
SKIP_BASE_RUN=false
CURRENT_BRANCH=$(git rev-parse --abbrev-ref HEAD)
BASE_BRANCH="main"

# Check if there are any uncommitted changes
check_git_status() {
    if [[ -n $(git status --porcelain) ]]; then
        echo "WARNING: You have uncommitted changes (modified, added, deleted, or untracked files)."
        echo "Please commit or stash your changes before running this script."
        echo "Use 'git status' to check the current state."
        exit 1
    fi
    echo "No uncommitted changes found. Safe to proceed."
}

# Check Python dependencies
check_python_dependencies() {
    echo "Checking Python dependencies..."
    for dependency in "${REQUIRED_PYTHON_DEPENDENCIES[@]}"; do
        if ! $PYTHON_CMD -c "import $dependency" &> /dev/null; then
            echo "ERROR: Python dependency '$dependency' is not installed!"
            echo "Please install it using: '$PYTHON_CMD -m pip install $dependency'"
            exit 1
        fi
    done
    echo "All required Python dependencies are installed."
}

# Run a command and check its exit status
run_command() {
    local command="$1"
    local error_message="$2"

    if ! eval "$command"; then
        echo "ERROR: $error_message"
        exit 1
    fi
}

# Running examples to generate log files
run_rust_command() {
    local branch=$1
    local prefix=$2
    local rust_cmd=$3

    if [[ "$SKIP_BASE_RUN" == false ]]; then
        echo "Switching to branch '$branch'..."
        run_command "git checkout $branch" "Failed to checkout branch '$branch'. Please check if the branch exists."
    fi

    # Log file location and name
    LOG_FILE="$LOG_DIR/test_${prefix}.log"
    mkdir -p "$LOG_DIR"

    echo "Running Rust command..."
    echo "Executing command: $rust_cmd"
    eval "$rust_cmd" > "$LOG_FILE" 2>&1

    # Check if the command was successful
    if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
        echo "ERROR: Failed to run Rust command. Please check the Rust setup or code. Error details:"
        echo "=== Last 20 lines of the log ==="
        tail -n 20 "$LOG_FILE"
        exit 1
    fi

    echo "Log saved to $LOG_FILE"
}

# 1. Ensure the execution is always from the project root directory
cd "$ROOT_DIR" || exit 1

# 2. Check Git status before proceeding
if [[ "$SKIP_BASE_RUN" == false ]]; then
    check_git_status
fi

# 3. Check Python dependencies before proceeding
check_python_dependencies

# 4. Loop over the Rust commands and log prefixes for batch processing
for i in "${!RUST_CMD_ARRAY[@]}"; do
    RUST_CMD="${RUST_CMD_ARRAY[i]}"
    LOG_PREFIX_0="${LOG_PREFIX_0_ARRAY[i]}"
    LOG_PREFIX_1="${LOG_PREFIX_1_ARRAY[i]}"

    # Run Rust commands to generate logs for the current branch and the base branch
    if [[ "$SKIP_BASE_RUN" == false ]]; then
        run_rust_command "$BASE_BRANCH" "$LOG_PREFIX_0" "$RUST_CMD"  # Base branch
    fi
    run_rust_command "$CURRENT_BRANCH" "$LOG_PREFIX_1" "$RUST_CMD"  # Current branch

    # Calling analyze.py for the current iteration
    echo "Calling analyze.py for log analysis with prefixes $LOG_PREFIX_0 and $LOG_PREFIX_1..."
    cd "$LOG_DIR" || exit 1
    cd .. || exit 1
    $PYTHON_CMD "$ANALYZE_SCRIPT" "$LOG_PREFIX_0" "$LOG_PREFIX_1" > "py_output_${i}.log" 2>&1

    if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
        echo "WARNING: Python analysis script encountered an error. Check 'py_output_${i}.log' for details, but proceeding with the rest of the script."
    fi

    echo "Analysis for iteration $i completed! Logs analyzed for current branch and main."

    # Return to project root directory after each iteration
    cd "$ROOT_DIR" || exit 1
done

# Return to the original directory
cd "$ORIGINAL_DIR" || exit 1

echo "All comparisons completed!"
