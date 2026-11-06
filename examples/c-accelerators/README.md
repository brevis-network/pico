# C guest: the accelerators

A freestanding C guest that calls every function of zkevm-standards' `zkvm_accelerators.h` on a
known answer, linked only against `libpico_zkvm.a` and `pico.ld` (see the static library in
`docs/guest-runtime.md`). It exits 0, or with the number of the first check that failed.

```bash
./build.sh                       # needs clang and ld.lld with the RISC-V target
cargo pico execute --elf build/guest.elf
```

`build.sh` downloads the header at a pinned zkevm-standards commit and builds the library with
`cargo pico lib`; set `PICO_SOURCE` to this checkout to build it from here. `vectors.h` holds
one case per function from the go-ethereum and execution-specs precompile tests.
