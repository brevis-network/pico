#!/bin/bash
# Runs the GPU trace-generation tests and CPU-vs-GPU benches; needs a CUDA toolkit and a GPU.
set -eo pipefail

. "$(dirname "$0")/detect_cuda.sh"
if ! pico_cuda_detect || [ "$PICO_BACKEND" != cuda ] || ! nvidia-smi -L 2>/dev/null | grep -q '^GPU '; then
    echo "run_all_tests.sh: these are GPU tests; they need a CUDA toolkit and a GPU" >&2
    exit 1
fi

tests=(
"test_byte_gpu_generate_preprocessed"
"test_riscv_poseidon2_gpu_generate_main"
"bench_riscv_poseidon2_cpu_vs_gpu"
"test_divrem_gpu_generate_extra_record_and_main"
"bench_divrem_cpu_vs_gpu"
"test_riscv_program_gpu_generate_extra_record_and_main"
"bench_riscv_program_cpu_vs_gpu"
"test_riscv_global_gpu_generate_extra_record_and_main"
"bench_riscv_global_cpu_vs_gpu"
"test_syscall_gpu_generate_extra_record_and_main"
"bench_syscall_cpu_vs_gpu"
"test_lt_gpu_generate_extra_record_and_main"
"test_bitwise_gpu_generate_extra_record_and_main"
"bench_bitwise_cpu_vs_gpu"
"test_keccak_gpu_generate_extra_record_and_main"
"test_sha_compress_gpu_generate_extra_record_and_main"
"bench_sha_compress_cpu_vs_gpu"
"test_sha_compress_control_gpu_generate_extra_record_and_main"
"bench_sha_compress_control_cpu_vs_gpu"
"test_sha_extend_gpu_generate_extra_record_and_main"
"bench_sha_extend_cpu_vs_gpu"
"test_sha_extend_control_gpu_generate_extra_record_and_main"
"bench_sha_extend_control_cpu_vs_gpu"
"test_memory_local_gpu_generate_extra_record_and_main"
"test_memory_init_finalize_gpu_generate_extra_record_and_main"
"test_memory_read_write_gpu_generate_extra_record_and_main"
"bench_memory_local_cpu_vs_gpu"
"bench_memory_init_finalize_cpu_vs_gpu"
"bench_memory_read_write_cpu_vs_gpu"
"test_secp256k1_addassign_generate_extra_record_and_main"
"test_bn254_addassign_generate_extra_record_and_main"
"test_bls12381_addassign_generate_extra_record_and_main"
"bench_weierstrass_add_cpu_vs_gpu"
"test_secp256k1_decompress_generate_extra_record_and_main"
"test_bls12381_decompress_generate_extra_record_and_main"
"bench_weierstrass_decompress_cpu_vs_gpu"
"test_bn254_fp_generate_extra_record_and_main"
"test_bls381_fp_generate_extra_record_and_main"
"test_secp256k1_fp_generate_extra_record_and_main"
"bench_fp_op_cpu_vs_gpu"
"test_bn254_fp2_add_sub_generate_extra_record_and_main"
"test_bls12381_fp2_add_sub_generate_extra_record_and_main"
"bench_fp2_add_sub_cpu_vs_gpu"
"test_bn254_fp2_mul_generate_extra_record_and_main"
"test_bls12381_fp2_mul_generate_extra_record_and_main"
"bench_fp2_mul_cpu_vs_gpu"
)

log=$(mktemp)
trap 'rm -f "$log"' EXIT
summary=()
for t in "${tests[@]}"; do
    echo "========================================="
    echo "Running $t"
    echo "========================================="
    cargo test --release -p pico-vm --features cuda --lib "$t" -- --nocapture 2>&1 | tee "$log"
    # A renamed or cfg'd-out test matches nothing, and cargo reports that as success.
    passed=$(awk '/^test result: ok\./ { n += $4 } END { print n + 0 }' "$log")
    if [ "$passed" -eq 0 ]; then
        echo "run_all_tests.sh: '$t' matched no test" >&2
        exit 1
    fi
    summary+=("$passed $t")
done
printf '%s\n' "${summary[@]}"
echo "All tests completed successfully!"
