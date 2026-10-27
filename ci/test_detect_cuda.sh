#!/usr/bin/env bash
# Tests for detect_cuda.sh, the GPU-or-CPU decision of the build entry points. Runs anywhere -- no
# CUDA, no GPU, no build: nvcc and nvidia-smi are stubs whose presence is the input.
#
#   ./ci/test_detect_cuda.sh
set -uo pipefail
cd "$(dirname "$0")/.."

PASS=0
FAIL=0

STUB_DIR="$(mktemp -d)"
trap 'rm -rf "$STUB_DIR"' EXIT
mkdir -p "$STUB_DIR/bin" "$STUB_DIR/toolkit/bin"
printf '#!/usr/bin/env bash\nexit 0\n' > "$STUB_DIR/toolkit/bin/nvcc"
# Lists FAKE_GPUS cards the way `nvidia-smi -L` does.
cat > "$STUB_DIR/bin/nvidia-smi" << 'STUB'
#!/usr/bin/env bash
for ((i = 0; i < ${FAKE_GPUS:-1}; i++)); do echo "GPU $i: NVIDIA GeForce RTX 5090 (UUID: GPU-$i)"; done
STUB
chmod +x "$STUB_DIR/toolkit/bin/nvcc" "$STUB_DIR/bin/nvidia-smi"

# Prints "<status> <backend>" for one decision. The stubs come first on PATH, ahead of the system
# directories the stubs themselves need (bash, grep).
detect() { # nvcc_on_path(0/1) fake_gpus [PICO_CUDA] [CUDA_PATH]
    local path="$STUB_DIR/bin"
    [ "$1" = 1 ] && path="$STUB_DIR/toolkit/bin:$path"
    env -i PATH="$path:/usr/bin:/bin" FAKE_GPUS="$2" \
        ${3:+PICO_CUDA=$3} ${4:+CUDA_PATH=$4} \
        bash -c '. ./detect_cuda.sh; pico_cuda_detect 2>/dev/null; echo "$? ${PICO_BACKEND:-none}"'
}

check() { # description expected actual
    if [ "$2" = "$3" ]; then
        PASS=$((PASS + 1))
        printf 'ok   %s\n' "$1"
    else
        FAIL=$((FAIL + 1))
        printf 'FAIL %s\n     want: %s\n     got:  %s\n' "$1" "$2" "$3"
    fi
}

check "nvcc and a GPU build for GPU" "0 cuda" "$(detect 1 1)"
check "no nvcc builds for CPU" "0 cpu" "$(detect 0 1)"
check "nvcc but no GPU builds for CPU" "0 cpu" "$(detect 1 0)"
check "nvcc through CUDA_PATH counts" "0 cuda" "$(detect 0 1 '' "$STUB_DIR/toolkit")"
check "PICO_CUDA=0 wins over a GPU" "0 cpu" "$(detect 1 1 0)"
check "PICO_CUDA=1 builds for GPU without a card" "0 cuda" "$(detect 1 0 1)"
check "PICO_CUDA=1 fails without nvcc" "1 none" "$(detect 0 1 1)"
check "PICO_CUDA must be 0 or 1" "1 none" "$(detect 1 1 yes)"

printf '%d passed, %d failed\n' "$PASS" "$FAIL"
[ "$FAIL" = 0 ]
