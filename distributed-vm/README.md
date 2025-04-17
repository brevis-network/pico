# Distributed VM

## Prerequisites

- Install `protoc` for development, run `brew install protobuf` for macOS and `apt-get install protobuf-compiler` for Ubuntu.

## TODO

### Coordinator

- [x] vm thread
- [ ] gateway thread
- [ ] server thread
  - [ ] receive start proving request from user
  - [ ] receive health request from worker for registration
  - [ ] send riscv proving request from vm
  - [ ] receive riscv proof response from worker
- [ ] grpc protocols

### Worker

- [x] riscv prover thread
- [ ] grpc client thread
  - [ ] send health request for worker registration
  - [ ] receive riscv proving request from coordinator
  - [ ] send riscv proof response to coordinator
