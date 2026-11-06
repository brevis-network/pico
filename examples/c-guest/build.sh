#!/usr/bin/env bash
# Builds the C guest twice, linked once with LLD and once with GNU ld, against the static library
# and linker script `cargo pico lib` wrote to $1 (default: ./pico-zkvm).
#
#   ./build.sh [lib-dir]      writes guest-lld.elf and guest-gnu-ld.elf
#
# CC / CXX default to clang / clang++; LLD defaults to ld.lld; GNU_LD to riscv64-unknown-elf-ld.
# Leave GNU_LD empty to skip that link.
set -euo pipefail
cd "$(dirname "$0")"

LIB=${1:-pico-zkvm}
CC=${CC:-clang}
CXX=${CXX:-clang++}
LLD=${LLD:-ld.lld}
GNU_LD=${GNU_LD-riscv64-unknown-elf-ld}

# RV64IM, the guest target; no C library, so freestanding; medany, because the image sits at
# 0x00200800, outside the default code model's +-2 GiB around 0.
TARGET=(--target=riscv64-unknown-elf -march=rv64im -mabi=lp64 -mcmodel=medany -O2 -ffreestanding)
"$CC" "${TARGET[@]}" -c main.c -o main.o
# No C++ standard library either: no exceptions, RTTI or guarded statics, which would need it.
"$CXX" "${TARGET[@]}" -nostdinc++ -fno-exceptions -fno-rtti -fno-threadsafe-statics \
    -c globals.cpp -o globals.o

OBJS=(main.o globals.o "$LIB/libpico_zkvm.a")
"$LLD" -T "$LIB/pico.ld" --gc-sections "${OBJS[@]}" -o guest-lld.elf
echo "linked guest-lld.elf with $LLD"
if [ -n "$GNU_LD" ]; then
    "$GNU_LD" -T "$LIB/pico.ld" --gc-sections "${OBJS[@]}" -o guest-gnu-ld.elf
    echo "linked guest-gnu-ld.elf with $GNU_LD"
fi
