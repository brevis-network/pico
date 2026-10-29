# Decides whether the build entry points (Makefile, single_node_mle.sh, ...) build the GPU prover.
# Source it, then call `pico_cuda_detect`, which sets PICO_BACKEND to `cuda` or `cpu` and prints the
# decision on stderr.
#
#   PICO_CUDA=1  GPU build; fails without a CUDA toolkit.
#   PICO_CUDA=0  CPU build.
#   unset        GPU build when nvcc runs (PATH, CUDA_PATH or CUDA_HOME) and nvidia-smi lists a GPU.
#
# A plain `cargo build` never detects anything: it is a CPU build unless `--features cuda` is given.

# Succeeds when nvcc runs; puts the toolkit found through CUDA_PATH / CUDA_HOME on PATH.
pico_cuda_nvcc() {
    local dir
    if nvcc --version >/dev/null 2>&1; then
        return 0
    fi
    for dir in "${CUDA_PATH:-}" "${CUDA_HOME:-}"; do
        if [ -n "$dir" ] && "$dir/bin/nvcc" --version >/dev/null 2>&1; then
            export PATH="$dir/bin:$PATH"
            return 0
        fi
    done
    return 1
}

# The toolkit release nvcc reports, e.g. `12.8`.
pico_cuda_version() {
    nvcc --version 2>/dev/null | sed -n 's/.*release \([0-9.]*\).*/\1/p'
}

pico_cuda_detect() {
    case "${PICO_CUDA:-}" in
        0)
            PICO_BACKEND=cpu
            echo "pico: CPU build (PICO_CUDA=0)" >&2
            return 0
            ;;
        1)
            if ! pico_cuda_nvcc; then
                echo "pico: PICO_CUDA=1 but no CUDA toolkit found (nvcc, CUDA_PATH, CUDA_HOME)" >&2
                return 1
            fi
            PICO_BACKEND=cuda
            echo "pico: GPU build with CUDA $(pico_cuda_version) (PICO_CUDA=1)" >&2
            return 0
            ;;
        '') ;;
        *)
            echo "pico: PICO_CUDA must be 0 or 1, not '$PICO_CUDA'" >&2
            return 1
            ;;
    esac
    if pico_cuda_nvcc && nvidia-smi -L 2>/dev/null | grep -q '^GPU '; then
        PICO_BACKEND=cuda
        echo "pico: GPU build with CUDA $(pico_cuda_version) (PICO_CUDA=0 builds for CPU)" >&2
    else
        PICO_BACKEND=cpu
        echo "pico: CPU build (no nvcc or no GPU; PICO_CUDA=1 builds for GPU)" >&2
    fi
}
