#!/bin/bash

# Script to run the proof test server for testing proof completion notifications
# This server listens for gRPC calls from the aggregator and prints the received data

set -e

# Default port (58888 to avoid conflict with aggregator/subblock services on 50053)
PORT="${PROOF_TEST_SERVER_PORT:-58888}"
ADDR="0.0.0.0:${PORT}"

echo "╔════════════════════════════════════════════════════════════════╗"
echo "║          PROOF TEST SERVER LAUNCHER                            ║"
echo "╚════════════════════════════════════════════════════════════════╝"
echo ""
echo "Building proof-test-server..."
echo ""

cd distributed-vm
cargo build --bin proof-test-server --release

echo ""
echo "════════════════════════════════════════════════════════════════"
echo "Starting server on ${ADDR}"
echo "════════════════════════════════════════════════════════════════"
echo ""
echo "To test with your aggregator:"
echo "  Set the proof service address:"
echo "  export PROOF_SERVICE_ADDR=http://localhost:${PORT}"
echo ""
echo "Press Ctrl+C to stop the server"
echo "════════════════════════════════════════════════════════════════"
echo ""

PROOF_TEST_SERVER_ADDR="${ADDR}" ../target/release/proof-test-server

