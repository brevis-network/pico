# Chips Refactor

## Update

- Delete `channel` and `chunk` in all lookups.

- Add `InteractionScope` to replace `chunk` in lookup, it has `Local` and `Global` types.

- Add `Shape`, it's used to collect chip information (padded to fixed).

- Add `debug_interactions` functions for lookup debugging.

- Add `CostEstimator`.

- Delete CPU chip in recursion, and replace with separate ones.

## Move Core Events to chips Module

- Check the Recursion Events

## Check nonce usage

### Register nonce

[register_nonces](https://github.com/succinctlabs/sp1/blob/6512b56296c2c5e53b10cce1a741173a3d2dde68/crates/core/executor/src/record.rs#L388)

[brevis-vm](https://github.com/brevis-network/brevis-vm/blob/717dfce395f42a3930dd4d948b65eabd4488bf33/vm/src/emulator/riscv/record.rs#L178)

### Check lookups with nonce

## Add Performance logs

- We may only care about the Emulation Record generation time and proving time
- The `BaseProvingKey` and `BaseVerifyingKey` should be only generated once
- Separate the trace generation time and the commitment generation time
- We only care about the commitment generation time for the Chip optimization
- Add the detailed tracing logs for the chips during the proving steps
- Add one or two (Fibonacci and Keccak?) Performance tests

## Move Range Check to a separate Chip

The main idea is separating the big table to small tables if could reduce the computation for the lookups.
We could check if could work with this refactor.

- Move the `U8Range` and `U16Range` from core `ByteChip`
- Move the `U12Range` and `U16Range` from Recursion `RangeCheckChip`
- Combine to one Chip including `U8Range`, `U12Range` and `U16Range`
- This Chip could be configured for the supported ranges

## Core CPU Chip

### Move memory columns to a new table

[riscv_cpu/memory](https://github.com/brevis-network/brevis-vm/tree/717dfce395f42a3930dd4d948b65eabd4488bf33/vm/src/chips/chips/riscv_cpu/memory)
[OpcodeSelectorCols](https://github.com/brevis-network/brevis-vm/blob/717dfce395f42a3930dd4d948b65eabd4488bf33/vm/src/chips/chips/riscv_cpu/opcode_selector/columns.rs#L26)
[OpcodeSpecificCols](https://github.com/brevis-network/brevis-vm/blob/717dfce395f42a3930dd4d948b65eabd4488bf33/vm/src/chips/chips/riscv_cpu/opcode_specific/columns.rs#L17)

## Recursion CPU Chip

- TODO: Need to check the performance, specially for the Extension field.

## Optimize Shift Left and Shift Right Chips

- Shift Right Chip is slow in [this Performance log](https://docs.google.com/spreadsheets/d/1HLy4eEuBpLahA4ytpsuf_WKScU0mqO2lAflXL40aCbM/edit?gid=1203222635#gid=1203222635)
- For Shift Right Chip, may separate the `SRL` and `SRA` opcodes
- Optimize the bit shift with a new Bit Shift Chip
- The inputs of Shift Bit Chip is all bytes and shift bit number, and the output is the shift result.
- We need to support both left and right shift in Bit Shift Chip.

## Debug constraint builder

### Original constraint debug builder

[debug_constraints](https://github.com/succinctlabs/sp1/blob/6512b56296c2c5e53b10cce1a741173a3d2dde68/crates/stark/src/debug.rs#L25)

### Collect original lookup calls

## Add tests to existing chips
