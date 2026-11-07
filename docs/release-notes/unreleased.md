# Unreleased changes on `main`

What `main` carries past `v3.1.1`. The version stays `3.1.1` until the next release is tagged.

## Breaking

- **New keys and whitelist.** Misaligned loads and stores are now proved (a new `MemoryUnaligned`
  chip), and every store, a precompile's write included, proves it misses the program's code. Every
  convert verifying key changes, and the whitelist is rebuilt: its root is
  `MLE_VK_ROOT` in `vm/src/mle/shape_vk_bins/mle_vk_root.txt`. A proof made by 3.1.x does not
  verify here, nor the other way round.
- **Execution follows the RISC-V target's rules.**
  - A load or store whose address is not a multiple of its width runs (Zicclsm), and is counted:
    `Execution::misaligned_accesses`, `PureExecution::misaligned_accesses` and
    `Proof::misaligned_accesses`.
  - An access ends the run below `0x1_0000` (`NullAccess`), in the stack guard (`StackOverflow`),
    past the top of memory (`InvalidMemoryAccess`), and, for a store, in the program's code
    (`StoreToCode`). A syscall's buffers are checked the same way.
  - A jump or taken branch to a target that is not 4-aligned ends the run at the jump
    (`MisalignedJumpTarget`); a target outside the program, 0 included, or running past the last
    instruction ends it too (`OutsideProgram`). A run ends normally only at `HALT`.

  See [docs/guest-runtime.md](../guest-runtime.md) for the exit codes.
- **ELF validation.** The loader rejects an ELF32, a segment both writable and executable, an
  execute-only segment, and an entry point outside the executable segments.
- **`execute` is pure execution.** It runs the guest to its halt without the proving pipeline; the
  previous `execute` is `execute_chunked`. Both follow the rules above and agree on the committed
  bytes, the cycles, the misaligned-access count and the reason a run ends.
- **AOT code must be regenerated.** `AOT_CODEGEN_STAMP` is 7, and the pure-mode ABI is version 2:
  run `cargo pico aot` again, and rebuild cached pure-mode libraries.
- **GPU kernels.** The `cuda` build pins pico-gpu at `edd0ceb`, its kernels for the code-range
  and stack-guard columns; the 3.1 kernels do not match this tree.

## Added

- **Compress proofs verify in `pico-verifier`.** `verify_compress` / `verify_compress_with` take a
  compress proof as a v4 envelope (`Proof::export_compress_v4`), with the checks `verify` runs on
  a combine root; neither entry point accepts the other's envelope. The envelope holds the proof
  alone: the whitelist has one compress key, which `pico-verifier` ships
  (`shipped_compress_vk`, from `vm/src/mle/shape_vk_bins/mle_compress_vk.bin`).
- **Compress on the GPU.** In a `cuda` build, a whitelist-mode `prove_to(Phase::Compress)` proves
  the root on the multi-card GPU pipeline, as `prove` does, then the compress layer on card 0.

- The `zkvm_accelerators.h` functions in `libpico_zkvm.a` (`examples/c-accelerators`).
- `malloc` for C guests on newlib, through the runtime's `sbrk`, which shares its heap with the Rust
  allocator (`examples/c-guest/malloc.c`).
- ACT4 `RV64IM_Zicclsm`: all 72 tests execute, prove and verify.

## Performance

- The AOT replay workers run recording blocks that write the records themselves.
- The chunk split counts what a precompile costs the RISC-V chunk, not each of its memory accesses.
- The GPU pipeline holds 16 history slots by default.
