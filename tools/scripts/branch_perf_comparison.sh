#!/bin/bash

# Path settings
ORIGINAL_DIR=$(pwd)
ROOT_DIR=$(git rev-parse --show-toplevel)
LOG_DIR="$ROOT_DIR/tools/log_analysis/logs"
ANALYZE_SCRIPT="$ROOT_DIR/tools/log_analysis/analyze.py"

# Python settings
PYTHON_CMD="/usr/bin/python3"
REQUIRED_PYTHON_DEPENDENCIES=("pandas" "collections" "json" "matplotlib" "numpy")

# Rust settings
EXAMPLE_NAME="test_riscv_machine"
RUST_LOG="info"
RUSTFLAGS="-Awarnings"
FRI_QUERIES="1"
CMD_ARGS="f 40"
FEATURES=""

# Comparison settings
SKIP_BASE_RUN=false # Important FLAG that determines the script's execution mode.
LOG_PREFIX_0="main_${EXAMPLE_NAME}_${CMD_ARGS// /_}" # Main branch
LOG_PREFIX_1="new_${EXAMPLE_NAME}_${CMD_ARGS// /_}" # Current branch
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

    $command
    if [[ $? -ne 0 ]]; then
        echo "ERROR: $error_message"
        exit 1
    fi
}

# Running examples to generate log files
run_rust_command() {
    local branch=$1
    local prefix=$2

    if [[ "$SKIP_BASE_RUN" == false ]]; then
      echo "Switching to branch '$branch'..."
      run_command "git checkout $branch" "Failed to checkout branch '$branch'. Please check if the branch exists."
    fi

    # Log file location and name
    LOG_FILE="$LOG_DIR/test_${prefix}.log"
    mkdir -p "$LOG_DIR"

    echo "Running Rust command for example '$EXAMPLE_NAME'..."

    # Run the Rust command and capture the output
    RUST_CMD="RUST_LOG=$RUST_LOG RUSTFLAGS=$RUSTFLAGS FRI_QUERIES=$FRI_QUERIES cargo run --release --example $EXAMPLE_NAME $FEATURES -- $CMD_ARGS"
    echo "Executing command: $RUST_CMD"
    eval "$RUST_CMD" > "$LOG_FILE" 2>&1

    # Check if the command was successful
    if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
        echo "ERROR: Failed to run Rust command. Please check the Rust setup or code. Error details:"
        echo "=== Last 20 lines of the log ==="
        tail -n 20 "$LOG_FILE"  # Display the last 20 lines of the log for debugging
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

# 4. Run Rust commands to generate logs for the current branch and the base branch
if [[ "$SKIP_BASE_RUN" == false ]]; then
    run_rust_command "$BASE_BRANCH" "$LOG_PREFIX_0"  # Base branch
fi
run_rust_command "$CURRENT_BRANCH" "$LOG_PREFIX_1"  # Current branch

# 4. Modify prefix in analyze.py
echo "Modifying analyze.py to set correct prefixes..."
sed -i "s/prefix_0 = .*/prefix_0 = '$LOG_PREFIX_0'/g" "$ANALYZE_SCRIPT"
sed -i "s/prefix_1 = .*/prefix_1 = '$LOG_PREFIX_1'/g" "$ANALYZE_SCRIPT"

# 5. Call analyze.py for log analysis
# Ensure the py analysis is always from the upper directory of logs/
cd "$LOG_DIR" || exit 1
cd .. || exit 1
echo "Calling analyze.py for log analysis..."
$PYTHON_CMD "$ANALYZE_SCRIPT" > "py_output.log" 2>&1

if [[ ${PIPESTATUS[0]} -ne 0 ]]; then
    echo "ERROR: Failed to run the Python analysis script. Please check the script or dependencies."
    exit 1
fi

cd "$ORIGINAL_DIR" || exit 1

echo "Comparison completed! Logs analyzed for current branch and main."
