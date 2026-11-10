# A C / C++ guest

A guest built without Rust or cargo, linked against only Pico's static library and linker script
(zkevm-standards: static library and linker script). `main.c` reads its input, writes it back as
the public output, and ends the way its first input byte picks; `globals.cpp` holds a C++ global
whose constructor runs before `main` and whose destructor appends `bye` to the output after it.
The cases are listed at the top of `main.c`. `malloc.c` is a second guest, on newlib's C library:
its `malloc`, `calloc`, `realloc` and `free`, growing the heap through the runtime's `sbrk`.

From this directory, with `cargo pico` installed (`../README.md`), clang, and LLD or GNU ld for
RISC-V:

```bash
cargo pico lib --output pico-zkvm   # libpico_zkvm.a and pico.ld
./build.sh                          # guest-lld.elf and guest-gnu-ld.elf
./check.sh guest-lld.elf            # every case, then a proof of the successful one
NEWLIB_GCC=riscv-none-elf-gcc ./build.sh && ./check.sh --malloc guest-newlib.elf
cargo pico execute --elf guest-lld.elf --input 0x00
```

`build.sh` links the same objects twice, with `ld.lld` and with `riscv64-unknown-elf-ld`
(`GNU_LD=<path>` for another name; `GNU_LD= ./build.sh` skips it). The GNU ld must be recent:
binutils 2.38, Ubuntu 22.04's `binutils-riscv64-unknown-elf`, rejects every object LLVM builds for
RV64IM, on the `zmmul` extension in its `.riscv.attributes`. CI uses xPack's `riscv-none-elf-ld`
(15.2.0-1). The guest uses no C or C++ standard library: what it needs from one,
`abort`, the `assert` hook and `__cxa_atexit`, the static library provides
(`docs/guest-runtime.md`).

CI builds both, and runs `check.sh` on each (`CPU · C guest, GNU ld and LLD`).
