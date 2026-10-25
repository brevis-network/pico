#!/usr/bin/env bash
# Aggregator Log Analysis Script
# 
# This script provides easy access to the new aggregator log analysis tools.
# It can process single log files or batch process multiple files.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ANALYZER="$SCRIPT_DIR/analyze_aggregator_log.py"
BATCH_ANALYZER="$SCRIPT_DIR/analyze_logs_batch.py"
STREAM_ANALYZER="$SCRIPT_DIR/stream_aggregator_log.py"

usage() {
    cat << EOF
Usage: $0 [OPTIONS] <log_file_or_directory>

Analyze aggregator log files and extract block performance metrics.

OPTIONS:
    -h, --help          Show this help message
    -b, --batch         Process multiple log files (batch mode)
    --stream            Run streaming analyzer (single file, tail mode)
    -t, --tag TAG       Add tag to CSV output
    -o, --output FILE   Specify output CSV file
    -v, --verbose       Enable verbose output
    --split-block-logs  Split log(s) into per-block files
    --split-dir DIR     Directory to write per-block logs
    --charts            Generate per-block timeline charts
    --charts-dir DIR    Directory to write charts
    --include-failed    Include failed blocks when splitting/charts
    --chart-workers N   Number of concurrent workers for charts (default: 4)

STREAM ALERT OPTIONS:
    --inactivity-timeout-secs N  Notify if no new results within N seconds (default: 120)
    --env-file PATH              Load environment variables from .env file
    --slack-webhook-url URL      Slack incoming webhook URL (alternative to token)
    --slack-token TOKEN          Slack bot token (alternative to webhook)
    --slack-channel CHANNEL      Slack channel or conversation ID
    --slack-username NAME        Username for webhook (default: aggregator-monitor)
    --slack-emoji :emoji:        Emoji icon for webhook (optional)

STREAMING OPTIONS:
    --poll-interval-secs N  Polling interval for tailing (default: 1)
    --stream-quiet          Suppress console progress output
    --no-numa               Do not pin streamer to NUMA node 0 (advanced)

EXAMPLES:
    # Analyze single log file
    $0 logs/aggregator-b23290390-g10000000.txt
    
    # Analyze single log file with custom output
    $0 -o results/analysis.csv logs/aggregator-b23290390-g10000000.txt
    
    # Batch analyze all log files in directory
    $0 --batch logs/
    
    # Batch analyze with tag
    $0 --batch --tag "experiment_1" logs/
    
    # Batch analyze specific files
    $0 --batch logs/aggregator-b23290390-g10000000.txt logs/aggregator-b23290391-g10000000.txt

OUTPUT:
    The script generates CSV files with the following columns:
    tag, kind, block, idx, status, cycles, e2e_s, log_file
    
    - tag: Optional tag (empty by default)
    - kind: Always "aggregator" for aggregator logs
    - block: Block number
    - idx: Index (empty for aggregator)
    - status: "OK" or "FAIL"
    - cycles: Total cycles executed
    - e2e_s: End-to-end execution time in seconds
    - log_file: Source log file path
EOF
}

# Default values
BATCH_MODE=false
STREAM_MODE=false
TAG=""
OUTPUT=""
VERBOSE=false
SPLIT_BLOCK_LOGS=false
SPLIT_DIR=""
CHARTS=false
CHARTS_DIR=""
INCLUDE_FAILED=false
CHART_WORKERS=4
POLL_INTERVAL_SECS=1
STREAM_QUIET=false
USE_NUMA=true
INACTIVITY_TIMEOUT_SECS=120
ENV_FILE=""
SLACK_WEBHOOK_URL=""
SLACK_TOKEN=""
SLACK_CHANNEL=""
SLACK_USERNAME="aggregator-monitor"
SLACK_EMOJI=""

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -h|--help)
            usage
            exit 0
            ;;
        -b|--batch)
            BATCH_MODE=true
            shift
            ;;
        --stream)
            STREAM_MODE=true
            shift
            ;;
        -t|--tag)
            if [[ $# -lt 2 ]]; then
                echo "Error: --tag requires an argument" >&2
                usage >&2
                exit 1
            fi
            TAG="$2"
            shift 2
            ;;
        -o|--output)
            if [[ $# -lt 2 ]]; then
                echo "Error: --output requires an argument" >&2
                usage >&2
                exit 1
            fi
            OUTPUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --poll-interval-secs)
            if [[ $# -lt 2 ]]; then
                echo "Error: --poll-interval-secs requires an argument" >&2
                usage >&2
                exit 1
            fi
            POLL_INTERVAL_SECS="$2"
            shift 2
            ;;
        --stream-quiet)
            STREAM_QUIET=true
            shift
            ;;
        --no-numa)
            USE_NUMA=false
            shift
            ;;
        --inactivity-timeout-secs)
            if [[ $# -lt 2 ]]; then
                echo "Error: --inactivity-timeout-secs requires an argument" >&2
                usage >&2
                exit 1
            fi
            INACTIVITY_TIMEOUT_SECS="$2"
            shift 2
            ;;
        --env-file)
            if [[ $# -lt 2 ]]; then
                echo "Error: --env-file requires an argument" >&2
                usage >&2
                exit 1
            fi
            ENV_FILE="$2"
            shift 2
            ;;
        --slack-webhook-url)
            if [[ $# -lt 2 ]]; then
                echo "Error: --slack-webhook-url requires an argument" >&2
                usage >&2
                exit 1
            fi
            SLACK_WEBHOOK_URL="$2"
            shift 2
            ;;
        --slack-token)
            if [[ $# -lt 2 ]]; then
                echo "Error: --slack-token requires an argument" >&2
                usage >&2
                exit 1
            fi
            SLACK_TOKEN="$2"
            shift 2
            ;;
        --slack-channel)
            if [[ $# -lt 2 ]]; then
                echo "Error: --slack-channel requires an argument" >&2
                usage >&2
                exit 1
            fi
            SLACK_CHANNEL="$2"
            shift 2
            ;;
        --slack-username)
            if [[ $# -lt 2 ]]; then
                echo "Error: --slack-username requires an argument" >&2
                usage >&2
                exit 1
            fi
            SLACK_USERNAME="$2"
            shift 2
            ;;
        --slack-emoji)
            if [[ $# -lt 2 ]]; then
                echo "Error: --slack-emoji requires an argument" >&2
                usage >&2
                exit 1
            fi
            SLACK_EMOJI="$2"
            shift 2
            ;;
        --split-block-logs)
            SPLIT_BLOCK_LOGS=true
            shift
            ;;
        --split-dir)
            if [[ $# -lt 2 ]]; then
                echo "Error: --split-dir requires an argument" >&2
                usage >&2
                exit 1
            fi
            SPLIT_DIR="$2"
            shift 2
            ;;
        --charts)
            CHARTS=true
            shift
            ;;
        --charts-dir)
            if [[ $# -lt 2 ]]; then
                echo "Error: --charts-dir requires an argument" >&2
                usage >&2
                exit 1
            fi
            CHARTS_DIR="$2"
            shift 2
            ;;
        --include-failed)
            INCLUDE_FAILED=true
            shift
            ;;
        --chart-workers)
            if [[ $# -lt 2 ]]; then
                echo "Error: --chart-workers requires an argument" >&2
                usage >&2
                exit 1
            fi
            CHART_WORKERS="$2"
            shift 2
            ;;
        -*)
            echo "Error: Unknown option $1" >&2
            usage >&2
            exit 1
            ;;
        *)
            break
            ;;
    esac
done

# Check if we have input files/directories
if [[ $# -eq 0 ]]; then
    echo "Error: No input files or directories specified" >&2
    usage >&2
    exit 1
fi

# Check if Python scripts exist
if [[ ! -f "$ANALYZER" ]]; then
    echo "Error: Analyzer script not found: $ANALYZER" >&2
    exit 1
fi

if [[ "$BATCH_MODE" == true && ! -f "$BATCH_ANALYZER" ]]; then
    echo "Error: Batch analyzer script not found: $BATCH_ANALYZER" >&2
    exit 1
fi

if [[ "$STREAM_MODE" == true && ! -f "$STREAM_ANALYZER" ]]; then
    echo "Error: Streaming analyzer script not found: $STREAM_ANALYZER" >&2
    exit 1
fi

# Build command arguments
ARGS=()
STREAM_ARGS=()

if [[ -n "$TAG" ]]; then
    ARGS+=("--tag" "$TAG")
    STREAM_ARGS+=("--tag" "$TAG")
fi

if [[ -n "$OUTPUT" ]]; then
    ARGS+=("--output" "$OUTPUT")
    # For streaming, positional output can also be passed; prefer --output
    STREAM_ARGS+=("$OUTPUT")
fi

# New flags
if [[ "$SPLIT_BLOCK_LOGS" == true ]]; then
    ARGS+=("--split-block-logs")
fi
if [[ -n "$SPLIT_DIR" ]]; then
    ARGS+=("--split-dir" "$SPLIT_DIR")
fi
if [[ "$CHARTS" == true ]]; then
    ARGS+=("--charts")
fi
if [[ -n "$CHARTS_DIR" ]]; then
    ARGS+=("--charts-dir" "$CHARTS_DIR")
fi
if [[ "$INCLUDE_FAILED" == true ]]; then
    ARGS+=("--include-failed")
fi
if [[ -n "$CHART_WORKERS" ]]; then
    ARGS+=("--chart-workers" "$CHART_WORKERS")
fi

# Add input files/directories
ARGS+=("$@")

# Streaming specific args
if [[ -n "$POLL_INTERVAL_SECS" ]]; then
    STREAM_ARGS+=("--poll-interval-secs" "$POLL_INTERVAL_SECS")
fi
if [[ "$STREAM_QUIET" == true ]]; then
    STREAM_ARGS+=("--quiet")
fi
if [[ -n "$INACTIVITY_TIMEOUT_SECS" ]]; then
    STREAM_ARGS+=("--inactivity-timeout-secs" "$INACTIVITY_TIMEOUT_SECS")
fi
if [[ -n "$ENV_FILE" ]]; then
    STREAM_ARGS+=("--env-file" "$ENV_FILE")
fi
if [[ -n "$SLACK_WEBHOOK_URL" ]]; then
    STREAM_ARGS+=("--slack-webhook-url" "$SLACK_WEBHOOK_URL")
fi
if [[ -n "$SLACK_TOKEN" ]]; then
    STREAM_ARGS+=("--slack-token" "$SLACK_TOKEN")
fi
if [[ -n "$SLACK_CHANNEL" ]]; then
    STREAM_ARGS+=("--slack-channel" "$SLACK_CHANNEL")
fi
if [[ -n "$SLACK_USERNAME" ]]; then
    STREAM_ARGS+=("--slack-username" "$SLACK_USERNAME")
fi
if [[ -n "$SLACK_EMOJI" ]]; then
    STREAM_ARGS+=("--slack-emoji" "$SLACK_EMOJI")
fi

# For streaming mode, require exactly one input path (a file)
if [[ "$STREAM_MODE" == true ]]; then
    if [[ $# -ne 1 ]]; then
        echo "Error: --stream requires exactly one log file path" >&2
        usage >&2
        exit 1
    fi
fi

# Run the appropriate analyzer
if [[ "$STREAM_MODE" == true ]]; then
    # NUMA pinning and low priority execution for minimal impact
    LOG_PATH="$1"
    if [[ "$VERBOSE" == true ]]; then
        echo "Running streaming analyzer with args: ${STREAM_ARGS[*]} ${LOG_PATH}"
    fi
    if [[ "$USE_NUMA" == true ]]; then
        numactl --cpunodebind=0 --membind=0 ionice -c3 nice -n 19 \
            python3 "$STREAM_ANALYZER" "$LOG_PATH" ${STREAM_ARGS[*]}
    else
        ionice -c3 nice -n 19 \
            python3 "$STREAM_ANALYZER" "$LOG_PATH" ${STREAM_ARGS[*]}
    fi
elif [[ "$BATCH_MODE" == true ]]; then
    if [[ "$VERBOSE" == true ]]; then
        echo "Running batch analyzer with args: ${ARGS[*]}"
    fi
    python3 "$BATCH_ANALYZER" "${ARGS[@]}"
else
    if [[ "$VERBOSE" == true ]]; then
        echo "Running single file analyzer with args: ${ARGS[*]}"
    fi
    python3 "$ANALYZER" "${ARGS[@]}"
fi

