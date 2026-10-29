# Proof Test Server

A gRPC test server for receiving and displaying proof completion notifications from the aggregator.

## Overview

This test server implements the `Proof` service defined in `distributed-vm/proto/proof.proto`. It listens for `CompleteProvingRequest` messages and displays the received information in a formatted output.

## Quick Start

### Method 1: Using the Helper Script (Recommended)

```bash
# Start the test server (runs on port 58888 by default)
./run-proof-test-server.sh

# Or specify a custom port
PROOF_TEST_SERVER_PORT=60000 ./run-proof-test-server.sh
```

### Method 2: Manual Start

```bash
# Build the server
cd distributed-vm
cargo build --bin proof-test-server --release

# Run the server
../target/release/proof-test-server

# Or with a custom address
PROOF_TEST_SERVER_ADDR=0.0.0.0:8080 ../target/release/proof-test-server
```

## Testing with Your Aggregator

1. **Start the test server** (in one terminal):
   ```bash
   ./run-proof-test-server.sh
   ```

2. **Configure your aggregator** (in another terminal):
   ```bash
   export PROOF_SERVICE_ADDR=http://localhost:58888
   
   # Optional: Set the cycle count
   export PROVING_CYCLES=1000000
   ```

3. **Run the prover that sends the notifications.**

## What You'll See

When the aggregator completes processing a block, the test server will display:

```
╔════════════════════════════════════════════════════════════════╗
║          PROOF COMPLETION NOTIFICATION RECEIVED               ║
╚════════════════════════════════════════════════════════════════╝
┌────────────────────────────────────────────────────────────────┐
│ Status       : ✓ SUCCESS
│ Block Number : 12345
│ Cycles       : 1000000
│ Proving Time : 45678 ms (45.68 seconds)
│ Proof Size   : 524288 bytes (512.00 KB, 0.50 MB)
│ Proof Preview: (first 64 bytes)
│   a1 b2 c3 d4 e5 f6 g7 h8 i9 j0 k1 l2 m3 n4 o5 p6
│   q7 r8 s9 t0 u1 v2 w3 x4 y5 z6 aa ab ac ad ae af
│   ...
└────────────────────────────────────────────────────────────────┘
```

## Configuration

### Environment Variables

- `PROOF_TEST_SERVER_ADDR` - Server bind address (default: `0.0.0.0:58888`)
- `PROOF_TEST_SERVER_PORT` - Server port when using the helper script (default: `58888`)

### Aggregator Environment Variables

- `PROOF_SERVICE_ADDR` - Address of the proof test server (e.g., `http://localhost:58888`)
- `PROVING_CYCLES` - Optional cycle count to include in the request (default: `0`)

## Protocol Details

The server implements the `Proof` service with the following method:

```protobuf
service Proof {
  rpc CompleteProving(CompleteProvingRequest) returns (google.protobuf.Empty);
}

message CompleteProvingRequest {
  bool success = 1;              // Whether proving succeeded
  uint64 block_number = 2;       // Block number
  uint64 cycles = 3;             // Emulation cycles
  uint64 proving_milliseconds = 4; // Proving time in milliseconds
  optional bytes proof = 5;      // Serialized proof bytes
}
```

## Features

- ✅ gRPC with Zstd compression support
- ✅ HTTP/2 with keepalive
- ✅ Pretty-printed output with formatted data
- ✅ Hex preview of proof bytes
- ✅ Human-readable file sizes (bytes, KB, MB)
- ✅ Structured logging with tracing
- ✅ Non-blocking - won't crash your aggregator if the server is down

## Troubleshooting

### Server won't start
- Check if port 58888 is already in use: `lsof -i :58888`
- Try a different port: `PROOF_TEST_SERVER_PORT=60000 ./run-proof-test-server.sh`

### Not receiving notifications
- Ensure `PROOF_SERVICE_ADDR` is set in your aggregator environment
- Check the aggregator logs for "complete-proving" messages
- Verify the server address matches (including http:// prefix)
- Ensure no firewall is blocking the connection

### Connection timeout
- Check network connectivity between aggregator and server
- Verify the server is running and listening
- Check aggregator logs for connection errors

## Development

To modify the server behavior:

1. Edit `distributed-vm/bin/proof_test_server.rs`
2. Rebuild: `cargo build --bin proof-test-server`
3. Restart the server

## Additional Notes

- The server is designed for testing and debugging only
- All received data is logged to stdout
- The server will continue running even if requests fail
- Multiple aggregators can connect to the same test server

