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
- the precompiles of `zkvm_accelerators.h` in zkevm-standards (`zkvm_keccak256`,
  `zkvm_bn254_pairing`, ...; `sdk/sdk/src/zkvm_accelerators`), and Pico's own syscalls
  (`syscall_*`) beneath them;
- `memcpy` / `memset`, and in the static library also `memmove`, `memcmp`, `bcmp` and `strlen`
  (see [Memory functions](#memory-functions));
- `abort`, and `__assert_func` / `__assert_fail`, which a failed `assert()` calls in newlib /
  picolibc and in glibc / musl;
- `atexit`, `__cxa_atexit` and `__dso_handle`, through which C++ registers its static
  destructors; `_start` runs the handlers after `main`, latest first, before `.fini_array`.

- `sbrk` / `_sbrk`, through which a C library's `malloc` grows its heap: newlib's, built for
  `rv64im` / `lp64`, works unchanged (`examples/c-guest/malloc.c`). They take the heap from the
  same bump pointer as the Rust allocator and `read_input`'s buffer, between `_heap_start` and
  `_heap_end`, so the two never overlap; a negative increment is refused, as is growth past
  `_heap_end`.

The C-library ones (`abort` through `_sbrk`) are weak, so a C library linked into the
guest that brings its own takes precedence instead of clashing.

The library carries the Rust standard library it is written against; `main` is left for the
guest. A C guest that uses no C library links like this:

```sh
cargo pico lib --output pico-zkvm
clang --target=riscv64-unknown-elf -march=rv64im -mabi=lp64 -mcmodel=medany -O2 \
      -ffreestanding -c main.c -o main.o
ld.lld -T pico-zkvm/pico.ld main.o pico-zkvm/libpico_zkvm.a --gc-sections -o guest.elf
```

GNU ld (`riscv64-unknown-elf-ld`) takes the same arguments, but must be recent: binutils 2.38
(Ubuntu 22.04's) rejects the objects LLVM builds for RV64IM, the library's included, on the `zmmul`
extension their `.riscv.attributes` name. `examples/c-guest` is a complete C and
C++ guest, built with both linkers in CI.

The crate it builds is generated in `~/.pico/lib` (`$PICO_LIB_CACHE`) and takes `pico-sdk` from
this CLI's release, or from the checkout at `$PICO_SOURCE`.

## Memory functions

`memcpy` and `memset` are the runtime's assembly (`sdk/sdk/src/memcpy.s`, `memset.s`), and every
guest must link them rather than another definition: a guest that links another runs correctly
but slower. reth's ELF once kept `compiler_builtins`' `memcpy` and retired 5 % more
instructions, and nothing reported it.

**How they win.** They are in the same `global_asm!` as `_start`, so in the same object file,
and every link takes that object because `_start` is the entry point. Their definitions are
strong; `compiler_builtins`', which the guest build enables with `compiler-builtins-mem`, are
weak. So a Rust guest needs no linker flag, and a C guest needs no `--whole-archive`. A C library
linked into the guest that defines its own `memcpy` strongly fails the link with a duplicate
symbol rather than silently replacing Pico's; put `libpico_zkvm.a` before it on the command line,
so that its object is taken first and the C library's `memcpy` is never pulled in.

**The static library.** `cargo pico lib` builds without `compiler-builtins-mem`, and the runtime
adds `memmove` (compiler-builtins' algorithm, in C: `memmove.c`), musl's `memcmp` (with `bcmp`)
and `strlen` to the same object, no slower than `compiler_builtins`' copies. `compiler_builtins`'
copies are hidden, and a C guest takes them in with the other builtins it needs; the linker would
then make the library's `memcpy` and `memset` hidden too, local symbols in the guest, which
zkevm-test-monitor's link check (`mem-link-*`) rejects.

**The check.** The runtime puts an alias on each, `__pico_memcpy` / `__pico_memset`, and
`cargo pico build` fails if the ELF's `memcpy` or `memset` is anywhere but at its alias. An ELF
without a symbol table, or built with a `pico-sdk` from before the aliases, cannot be checked and
only gets a warning.

**The tests.** `vm/examples/patch-testing/guests/memory-functions` checks `memcpy`, `memset` and
`memmove` (`compiler_builtins`') against byte-by-byte references at every source and
destination alignment, lengths 0 to 40 and three longer ones, and `memmove` over overlapping
ranges both ways; `sdk/prover/src/tests/memory_functions.rs` runs it.

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

## ELF loading

The loader (`vm/src/compiler/riscv/disassembler/elf.rs`) takes the image from the `PT_LOAD`
segments alone, never the section headers, and rejects an ELF before anything runs or is proved
unless (zkevm-standards: ELF loading and validation):

- it is ELF64, little-endian, `EM_RISCV`, `ET_EXEC`;
- every segment is 4-aligned, at or above `0x0001_0000`, inside guest memory, and segments do not
  overlap and are in ascending address order;
- no segment is both writable and executable (W^X);
- every executable segment is `PF_X | PF_R` (below);
- the executable segments form one gapless run, ascending: together they are the instruction
  table, which indexes an instruction by its distance from the first one;
- `e_entry` is 4-aligned and inside that run.

**Permission model: execute-and-read.** Pico accepts executable segments flagged `PF_X | PF_R`
and rejects execute-only (`PF_X` alone) ones. Code bytes are in the memory image, so a load from
an executable segment returns the byte that executes there, and read-only data may share the
segment with code. `pico.ld` gives code its own `R X` segment and read-only data a separate `R`
one anyway.

## `_start`

1. Sets `gp` (`__global_pointer$`) and `sp` (`_stack_top`).
2. Initialises IO: the public-values hasher and the deferred-proof digest.
3. Runs `.preinit_array` and `.init_array`: C++ static constructors.
4. Calls `int main(void)`.
5. Runs the `atexit` / `__cxa_atexit` handlers, latest first: C++'s static destructors.
6. Runs `.fini_array` in reverse.
7. Halts with `main`'s return value.

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
| a jump or taken branch to an address that is not 4-aligned (after `JALR` clears bit 0) | `MisalignedJumpTarget { pc, target }`, at the jump | 135 (128 + SIGBUS) |
| a jump or taken branch out of the program, 0 included, or running past its last instruction | `OutsideProgram { pc }` | 139 (128 + SIGSEGV) |

Faults the emulator detects take the code a native process gets for the same signal. A run ends
only at `HALT`: a jump to 0 is not one, and neither is running off the end of the program. A
misaligned target is never rounded down (zkevm-standards: instruction-address-misaligned
exception semantics). A runtime
failure passes its reason to `HALT` in `a1` (`error::halt_reason`); a guest's own non-zero exit
leaves it `0`. The tags carry a prefix, so whatever an older runtime left in `a1` reads as a
plain `Exit`.

