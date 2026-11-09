#!/usr/bin/env bash
# Builds build/guest.elf: zkevm-standards' header, the Pico library, then clang and ld.lld.
# CC and LD pick the compiler and linker; both need the RISC-V target.
set -euo pipefail
cd "$(dirname "$0")"

# The zkevm-standards commit the header is taken from.
STANDARDS=f433d48d56e8a454a06c24f6c8a02f7156d9bfe1
CC=${CC:-clang}
LD=${LD:-ld.lld}

mkdir -p build
curl -fsSL -o build/zkvm_accelerators.h \
    "https://raw.githubusercontent.com/eth-act/zkevm-standards/$STANDARDS/standards/c-interface-accelerators/zkvm_accelerators.h"
cargo pico lib --output build/pico-zkvm
"$CC" --target=riscv64-unknown-elf -march=rv64im -mabi=lp64 -mcmodel=medany -O2 \
    -ffreestanding -std=c11 -Wall -Wextra -Werror -Ibuild -c main.c -o build/main.o
"$LD" -T build/pico-zkvm/pico.ld build/main.o build/pico-zkvm/libpico_zkvm.a --gc-sections \
    -o build/guest.elf
echo "built $(pwd)/build/guest.elf"
