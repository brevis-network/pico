# Guest runtime: `_start`, memory layout and exit codes

What a Pico guest runs before and after its own code, and where it lives in memory, as the
zkevm-standards guest interface asks for: a static library, `_start`, a linker script and a memory
layout.

## Linker script

`sdk/sdk/pico.ld` describes the layout below. `cargo pico build` links every Rust guest with it
(it writes a copy to the target directory and passes `-T`); a guest built some other way must
pass it too, since `_start` and the heap allocator read its symbols.

It places code, read-only data and writable data in three `PT_LOAD` segments, `R X`, `R` and
`R W`, so no segment is both writable and executable and the executable one holds only
instructions. It exports `_heap_start` and `_heap_end` for allocators.

## Static library

`cargo pico lib --output <dir>` writes `libpico_zkvm.a` and `pico.ld` to `<dir>`: everything a
guest needs from Pico, for a guest built without `cargo pico build`. The library is `pico-sdk`
compiled as a static library, so a Rust guest and a C guest get the same symbols, with C ABI:

- `_start`;
- `read_input` / `write_output` (`zkvm_io.h` in zkevm-standards);
- the accelerators (`syscall_*`);
- `memcpy` / `memset`;
- `abort`, and `__assert_func` / `__assert_fail`, which a failed `assert()` calls in newlib /
  picolibc and in glibc / musl. These three are weak, so a C library linked into the guest that
  brings its own takes precedence instead of clashing.

The library carries the Rust standard library it is written against; `main` is left for the
guest. A C guest that uses no C library links like this:

```sh
cargo pico lib --output pico-zkvm
clang --target=riscv64-unknown-elf -march=rv64im -mabi=lp64 -mcmodel=medany -O2 \
      -ffreestanding -c main.c -o main.o
ld.lld -T pico-zkvm/pico.ld main.o pico-zkvm/libpico_zkvm.a --gc-sections -o guest.elf
```

The crate it builds is generated in `~/.pico/lib` (`$PICO_LIB_CACHE`) and takes `pico-sdk` from
this CLI's release, or from the checkout at `$PICO_SOURCE`.

## Memory layout

| address | region |
|---|---|
| `0x0000_0000`–`0x0001_0000` | unusable: the register file, and no access below `2^16` is provable |
| `0x0020_0800` | code, then read-only data, then `.data` / `.bss` |
| `_heap_start` | heap, growing up: the first 16-byte-aligned address after `.bss` |
| `_heap_end` = `0x777f_0000` | stack guard, 64 KiB: nothing valid is stored here |
| `0x7780_0000` | stack, 8 MiB, growing down |
| `0x7800_0000` | `_stack_top`, the end of guest memory |

Every address stays below `0x7800_0000` so that it is a single KoalaBear element (the prime is
`0x7f00_0001`).

The values have one definition, `vm/src/primitives/layout.rs`, used by the emulator and the ELF
loader. The linker script carries its own copy, and `layout::tests::pico_ld_matches_this_layout`
fails if the two differ.

**The stack size is fixed**, the same for every program, so a check of the guard needs no
per-program input. 8 MiB is about 150 times the deepest stack reth reaches (52 KiB, on blocks
17106222, 18884864, 24004465, 24005809 and 24600825); its heap peaks at 56 MiB on 24600825.

## `_start`

1. Sets `gp` (`__global_pointer$`) and `sp` (`_stack_top`).
2. Initialises IO: the public-values hasher and the deferred-proof digest.
3. Runs `.preinit_array` and `.init_array`: C++ static constructors.
4. Calls `int main(void)`.
5. Runs `.fini_array` in reverse: static destructors.
6. Halts with `main`'s return value.

The loader zeroes `.bss`; `_start` does not.

A Rust guest declares its entry function with `pico_sdk::entrypoint!`. It may return `()`, which
is success, or an `i32` exit code.

## IO: `read_input` and `write_output`

The runtime exports the zkevm-standards IO interface (`zkvm_io.h`) with C ABI, from
`sdk/sdk/src/zkvm_io.rs`.

| | guest | host (`pico_prover`) |
|---|---|---|
| input | `read_input(&ptr, &size)`, or `pico_sdk::io::input()` in Rust | `Stdin::from_input(block)` |
| output | `write_output(ptr, size)`, or `pico_sdk::io::commit_bytes` | `Execution::committed_bytes`, `Proof::committed()` |

- **The input is one block, handed over unchanged:** no length prefix, no encoding. On the host
  it is one element of the input stream.
- **The first `read_input` call reads it.** It reads the next element into a buffer from the
  bump allocator, and every later call returns the same pointer and length.
- **`_start` does not read it.** A guest that never calls `read_input` keeps its stream intact:
  a Rust guest on `pico_sdk::io::read_vec` reads from the first element as before.
- **The input can be as large as the heap left when `read_input` first runs.**
- **An empty input is still one element**, which `read_input` returns with size 0. A run with no
  element left fails at `read_input` (`InsufficientInput`).
- **The output is the concatenation of every `write_output` call.** `write_output` writes to the
  public-values descriptor, so the bytes go into the SHA-256 that `_start` commits at the halt,
  and the proof binds them. `write_output(NULL, 0)` writes nothing.

## Exit codes and abnormal termination

`main` returns a C `int`; the halt takes it as a 32-bit value. Zero is success. Anything else
ends the run abnormally, and no proof of it verifies: Pico is a Type 1 zkVM under the
zkevm-standards termination semantics.

The host sees the 32-bit two's complement of the value, so the full `int` range survives:
`return 256` arrives as 256, and `return -1` as `4294967295`.

Every abnormal end reaches the host as one error, `EmulationError::AbnormalTermination`: a
reason and an exit code. Guest halts and faults the emulator detects both report through it, the
same way in the interpreter and the AOT emulator:

| what happened | reason | exit code |
|---|---|---|
| `main` returned non-zero, or `syscall_halt(n)` | `Exit` | `n` |
| Rust panic | `Panic` | 101, as a panicking Rust process exits |
| C `abort()`, or a failed `assert()` | `Abort` | 134 (128 + SIGABRT) |
| heap exhausted | `OutOfMemory` | 134 (128 + SIGABRT) |
| `unimp`, which is also what Rust's `std::process::abort` and a panic with a non-string payload end in | `IllegalInstruction { pc }` | 132 (128 + SIGILL) |
| `ebreak` | `Breakpoint { pc }` | 133 (128 + SIGTRAP) |
| a load or store the emulator does not allow | `InvalidMemoryAccess { opcode, addr }` | 139 (128 + SIGSEGV) |

Faults the emulator detects take the code a native process gets for the same signal. A runtime
failure passes its reason to `HALT` in `a1` (`error::halt_reason`); a guest's own non-zero exit
leaves it `0`. The tags carry a prefix, so whatever an older runtime left in `a1` reads as a
plain `Exit`.

