// other hpps
#include "tracegen/recursion/batch_fri.cuh"
#include "tracegen/riscv/byte.cuh"
#include "tracegen/recursion/exp_bits.cuh"
#include "tracegen/riscv/instruction.cuh"
#include "tracegen/precompiles/keccak_consts.cuh"
#include "tracegen/precompiles/keccak_permute.cuh"
#include "tracegen/common/poseidon2.cuh"
#include "tracegen/recursion/public_values.cuh"
#include "tracegen/recursion/recursion_memory_const.cuh"
#include "tracegen/recursion/recursion_memory_var.cuh"
#include "tracegen/recursion/recursion_poseidon2.cuh"
#include "tracegen/recursion/select.cuh"
#include "tracegen/common/warmup.cuh"
#include "tracegen/precompiles/curve_op.cuh"
#include "tracegen/precompiles/edwards_op.cuh"
#include "tracegen/precompiles/fp2_op.cuh"
#include "tracegen/precompiles/fp_lt.cuh"
#include "tracegen/precompiles/keccak_consts.cuh"
#include "tracegen/precompiles/keccak_permute.cuh"
#include "tracegen/precompiles/keccak_populate.cuh"
#include "tracegen/precompiles/keccak_control.cuh"
#include "tracegen/precompiles/keccak_round.cuh"
#include "tracegen/riscv/memory_initialize_finalize.cuh"
#include "tracegen/precompiles/precompile_ed_add_ed25519.cuh"
#include "tracegen/precompiles/precompile_ed_decompress.cuh"
#include "tracegen/precompiles/precompile_fp2_add_sub_bls12381.cuh"
#include "tracegen/precompiles/precompile_fp2_add_sub_bn254.cuh"
#include "tracegen/precompiles/precompile_fp2_mul_bls12381.cuh"
#include "tracegen/precompiles/precompile_fp2_mul_bn254.cuh"
#include "tracegen/precompiles/precompile_fp_op_bls381.cuh"
#include "tracegen/precompiles/precompile_fp_op_bn254.cuh"
#include "tracegen/precompiles/precompile_fp_op_secp256k1.cuh"
#include "tracegen/precompiles/precompile_poseidon2.cuh"
#include "tracegen/precompiles/precompile_sha256_compress.cuh"
#include "tracegen/precompiles/precompile_sha256_extend.cuh"
#include "tracegen/precompiles/precompile_uint256_mul.cuh"
#include "tracegen/precompiles/precompile_weierstrass_add_bls12381.cuh"
#include "tracegen/precompiles/precompile_weierstrass_add_bn254.cuh"
#include "tracegen/precompiles/precompile_weierstrass_add_secp256k1.cuh"
#include "tracegen/precompiles/precompile_weierstrass_add_secp256r1.cuh"
#include "tracegen/precompiles/precompile_weierstrass_decompress_bls12381.cuh"
#include "tracegen/precompiles/precompile_weierstrass_decompress_secp256k1.cuh"
#include "tracegen/precompiles/precompile_weierstrass_decompress_secp256r1.cuh"
#include "tracegen/precompiles/precompile_weierstrass_double_bls12381.cuh"
#include "tracegen/precompiles/precompile_weierstrass_double_bn254.cuh"
#include "tracegen/precompiles/precompile_weierstrass_double_secp256k1.cuh"
#include "tracegen/precompiles/precompile_weierstrass_double_secp256r1.cuh"
#include "tracegen/riscv/riscv_memory_local.cuh"
#include "tracegen/precompiles/sha256_operations.cuh"
#include "tracegen/riscv/syscall.cuh"
#include "tracegen/riscv/ecall.cuh"
// Packed-event (MLE_PACKED_EVENTS=1) ecall kernel
#include "tracegen/riscv/packed_ecall.cuh"

namespace pico_gpu {
  namespace warmup {
    PICO_FFI
    void cuda_warmup() { warmup(); } // cuda_warmup
  } // namespace warmup

  namespace byte {
    PICO_FFI
    RustError::by_value cuda_byte_generate_preprocessed(field_t* trace, const size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(trace, num_cols, stream);
    } // cuda_byte_generate_preprocessed
  } // namespace byte

  namespace weierstrass_add::secp256k1 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_add_secp256k1_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const EllipticCurveAddEvent_t* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    } // cuda_weierstrass_add_secp256k1_generate_main
  } // namespace weierstrass_add::secp256k1

  namespace weierstrass_add::secp256r1 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_add_secp256r1_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const EllipticCurveAddEvent_t* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    } // cuda_weierstrass_add_secp256r1_generate_main
  } // namespace weierstrass_add::secp256r1

  namespace weierstrass_add::bn254 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_add_bn254_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const EllipticCurveAddEvent_t* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    } // cuda_weierstrass_add_bn254_generate_main
  } // namespace weierstrass_add::bn254

  namespace weierstrass_add::bls12381 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_add_bls12381_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const EllipticCurveAddEvent_t* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    } // cuda_weierstrass_add_bls12381_generate_main
  } // namespace weierstrass_add::bls12381

  namespace weierstrass_double::secp256k1 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_double_secp256k1_generate_extra_record_and_main(
      const EllipticCurveDoubleEvent_t* events,
      size_t num_events,
      field_t* trace,
      size_t num_rows,
      size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(events, num_events, trace, num_rows, num_cols, byte_trace, stream);
    } // cuda_weierstrass_double_secp256k1_generate_main
  } // namespace weierstrass_double::secp256k1

  namespace weierstrass_double::secp256r1 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_double_secp256r1_generate_extra_record_and_main(
      const EllipticCurveDoubleEvent_t* events,
      size_t num_events,
      field_t* trace,
      size_t num_rows,
      size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(events, num_events, trace, num_rows, num_cols, byte_trace, stream);
    } // cuda_weierstrass_double_secp256r1_generate_main
  } // namespace weierstrass_double::secp256r1

  namespace weierstrass_double::bn254 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_double_bn254_generate_extra_record_and_main(
      const EllipticCurveDoubleEvent_t* events,
      size_t num_events,
      field_t* trace,
      size_t num_rows,
      size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(events, num_events, trace, num_rows, num_cols, byte_trace, stream);
    } // cuda_weierstrass_double_bn254_generate_main
  } // namespace weierstrass_double::bn254

  namespace weierstrass_double::bls12381 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_double_bls12381_generate_extra_record_and_main(
      const EllipticCurveDoubleEvent_t* events,
      size_t num_events,
      field_t* trace,
      size_t num_rows,
      size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(events, num_events, trace, num_rows, num_cols, byte_trace, stream);
    } // cuda_weierstrass_double_bls12381_generate_main
  } // namespace weierstrass_double::bls12381

  namespace weierstrass_decompress::bls12381 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_decompress_bls12381_generate_extra_record_and_main(
      const EllipticCurveDecompressEvent_t* events,
      size_t num_events,
      field_t* trace,
      size_t num_rows,
      size_t num_cols,
      size_t num_lexi_cols,
      bool lexi,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(
        events, num_events, trace, num_rows, num_cols, num_lexi_cols, lexi, byte_trace, stream);
    } // cuda_weierstrass_decompress_bls12381_generate_main
  } // namespace weierstrass_decompress::bls12381

  namespace weierstrass_decompress::secp256k1 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_decompress_secp256k1_generate_extra_record_and_main(
      const EllipticCurveDecompressEvent_t* events,
      size_t num_events,
      field_t* trace,
      size_t num_rows,
      size_t num_cols,
      size_t num_lexi_cols,
      bool lexi,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(
        events, num_events, trace, num_rows, num_cols, num_lexi_cols, lexi, byte_trace, stream);
    } // cuda_weierstrass_decompress_secp256k1_generate_main
  } // namespace weierstrass_decompress::secp256k1

  namespace weierstrass_decompress::secp256r1 {
    PICO_FFI
    RustError::by_value cuda_weierstrass_decompress_secp256r1_generate_extra_record_and_main(
      const EllipticCurveDecompressEvent_t* events,
      size_t num_events,
      field_t* trace,
      size_t num_rows,
      size_t num_cols,
      size_t num_lexi_cols,
      bool lexi,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(
        events, num_events, trace, num_rows, num_cols, num_lexi_cols, lexi, byte_trace, stream);
    } // cuda_weierstrass_decompress_secp256r1_generate_main
  } // namespace weierstrass_decompress::secp256r1

  namespace ed_add::ed25519 {
    PICO_FFI
    RustError::by_value cuda_edwards_add_ed25519_generate_extra_record_and_main(
      const EllipticCurveAddEvent_t* events,
      const size_t num_events,
      field_t* trace,
      const size_t num_rows,
      const size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(events, num_events, trace, num_rows, num_cols, byte_trace, stream);
    } // cuda_edwards_add_ed25519_generate_main
  } // namespace ed_add::ed25519

  namespace ed_decompress {
    PICO_FFI
    RustError::by_value cuda_edwards_decompress_generate_extra_record_and_main(
      const EdDecompressEvent* events,
      const size_t num_events,
      field_t* trace,
      const size_t num_rows,
      const size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(events, num_events, trace, num_rows, num_cols, byte_trace, stream);
    } // cuda_edwards_add_ed25519_generate_main
  } // namespace ed_decompress

  namespace select {
    PICO_FFI
    RustError::by_value cuda_select_generate_preprocessed(
      const SelectInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_select_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_select_generate_main(
      const SelectEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_select_generate_main
  } // namespace select

  namespace public_values {
    PICO_FFI
    RustError::by_value
    cuda_public_values_generate_preprocessed(const field_t* addrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(addrs, trace, num_cols, stream);
    } // cuda_public_values_generate_preprocessed
    PICO_FFI
    RustError::by_value
    cuda_public_values_generate_main(const field_t* digest, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(digest, trace, num_cols, stream);
    } // cuda_public_values_generate_main
  } // namespace public_values

  namespace exp_bits {
    PICO_FFI
    RustError::by_value cuda_exp_bits_generate_preprocessed(
      const ExpReverseBitsInstrFfi<field_t>* instrs,
      size_t instrs_len,
      const Address<field_t>* addrs,
      field_t* trace,
      size_t num_cols,
      cudaStream_t stream)
    {
      return generate_preprocessed(instrs, instrs_len, addrs, trace, num_cols, stream);
    } // cuda_exp_bits_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_exp_bits_generate_main(
      const ExpReverseBitsFfiEvent<field_t>* events,
      size_t events_len,
      field_t* bits,
      field_t* trace,
      size_t num_cols,
      cudaStream_t stream)
    {
      return generate_main(events, events_len, bits, trace, num_cols, stream);
    } // cuda_exp_bits_generate_main
  } // namespace exp_bits

  namespace batch_fri {
    PICO_FFI
    RustError::by_value cuda_batch_fri_generate_preprocessed(
      const BatchFRIInstrFfi<field_t>* instrs,
      size_t num_instrs,
      const Address<field_t>* p_at_x,
      const Address<field_t>* p_at_z,
      const Address<field_t>* alpha_pow,
      field_t* trace,
      size_t num_cols,
      cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, p_at_x, p_at_z, alpha_pow, trace, num_cols, stream);
    } // cuda_batch_fri_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_batch_fri_generate_main(
      const BatchFRIEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_batch_fri_generate_main
  } // namespace batch_fri

  namespace recursion_memory_const {
    PICO_FFI
    RustError::by_value cuda_recursion_mem_const_generate_preprocessed(
      const MemInstrFfi<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_recursion_mem_const_generate_preprocessed
  } // namespace recursion_memory_const

  namespace recursion_memory_var {
    PICO_FFI
    RustError::by_value cuda_recursion_mem_var_generate_preprocessed(
      const RecursionMemoryAccessCols<field_t>* instrs,
      size_t num_instrs,
      field_t* trace,
      size_t num_cols,
      cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_recursion_mem_var_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_recursion_mem_var_generate_main(
      const MemEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_recursion_mem_var_generate_main
  } // namespace recursion_memory_var

  namespace recursion_poseidon2 {
    PICO_FFI
    RustError::by_value cuda_recursion_poseidon2_generate_preprocessed(
      const Poseidon2SkinnyInstr<field_t>* instrs,
      const size_t num_instrs,
      field_t* trace,
      const size_t num_cols,
      cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    }
    PICO_FFI
    RustError::by_value cuda_recursion_poseidon2_generate_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const RecursionPoseidon2EventT* events,
      field_t* trace,
      field_t* dummy_row,
      const field_t* round_constants,
      cudaStream_t stream)
    {
      return generate_main(
        num_cols, event_size, trace_size, events, trace, dummy_row, round_constants, stream);
    }
  } // namespace recursion_poseidon2

  namespace byte {
    PICO_FFI
    RustError::by_value
    cuda_extra_record_initialize_byte_trace(field_t* d_byte_trace, size_t byte_trace_size, cudaStream_t stream)
    {
      return initialize_byte_trace(d_byte_trace, byte_trace_size, stream);
    }

    PICO_FFI
    RustError::by_value
    cuda_extra_record_finalize_byte_trace(field_t* d_byte_trace, size_t byte_trace_size, cudaStream_t stream)
    {
      return finalize_byte_trace(d_byte_trace, byte_trace_size, stream);
    }
  } // namespace byte

  namespace memory_initialize_finalize_u64 {
    PICO_FFI
    RustError::by_value cuda_memory_initialize_finalize_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const MemoryInitializeFinalizeEventU64* events,
      const uint32_t* previous_addr_limbs,
      field_t* trace,
      GlobalInteractionEvent* global_events,
      size_t global_events_start_index,
      bool is_receive,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, previous_addr_limbs, trace, global_events,
        global_events_start_index, is_receive, byte_trace, stream);
    }
  } // namespace memory_initialize_finalize_u64

  namespace riscv_memory_local_u64 {
    PICO_FFI
    RustError::by_value cuda_memory_local_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const MemoryLocalEventU64* events,
      field_t* trace,
      cudaStream_t stream,
      GlobalInteractionEvent* global_events,
      size_t global_events_start_index,
      field_t* byte_trace)
    {
      return generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, stream, global_events, global_events_start_index, byte_trace);
    }
  } // namespace riscv_memory_local_u64

  namespace syscall_u64 {
    PICO_FFI
    RustError::by_value cuda_syscall_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const SyscallEventU64* events,
      field_t* trace,
      cudaStream_t stream,
      GlobalInteractionEvent* global_events,
      size_t global_events_start_index,
      SyscallChunkKind chunk_kind,
      field_t* byte_trace)
    {
      return pico_gpu::syscall_u64::generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, stream, global_events, global_events_start_index, chunk_kind,
        byte_trace);
    }
  } // namespace syscall_u64

  namespace ecall_u64 {
    PICO_FFI
    RustError::by_value cuda_ecall_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const FfiCpuEventU64* events,
      field_t* trace,
      cudaStream_t stream,
      field_t* byte_trace)
    {
      return pico_gpu::ecall_u64::generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, stream, byte_trace);
    }
  } // namespace ecall_u64

  namespace ecall_u64_packed {
    PICO_FFI
    RustError::by_value cuda_ecall_generate_extra_record_and_main_u64_packed(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const FfiCpuEventPacked* events,
      size_t chunk,
      field_t* trace,
      cudaStream_t stream,
      field_t* byte_trace,
      size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main_packed(
        num_cols, event_size, trace_size, events, (uint32_t)chunk, trace, stream, byte_trace);
    }
  } // namespace ecall_u64_packed

  namespace precompile_poseidon2 {
    PICO_FFI
    RustError::by_value cuda_precompile_poseidon2_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const Poseidon2PermuteEvent* events,
      field_t* trace,
      field_t* dummy_row,
      const field_t* round_constants,
      cudaStream_t stream,
      field_t* byte_trace)
    {
      return generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, dummy_row, round_constants, stream, byte_trace);
    }
  } // namespace precompile_poseidon2

  namespace keccak {
    PICO_FFI
    RustError::by_value cuda_precompile_keccak_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const KeccakPermuteEvent* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    } // cuda_precompile_keccak_generate_extra_record_and_main
    PICO_FFI
    RustError::by_value cuda_precompile_keccak_control_generate_extra_record_and_main(
      const KeccakPermuteEvent* events,
      size_t events_len,
      field_t* trace,
      size_t total_rows,
      size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_control_extra_record_and_main(events, events_len, trace, total_rows, num_cols, byte_trace, stream);
    } // cuda_precompile_keccak_control_generate_extra_record_and_main
  } // namespace keccak

  namespace precompile_uint256_mul {
    PICO_FFI
    RustError::by_value cuda_precompile_uint256_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const Uint256MulEvent* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace precompile_uint256_mul

  namespace precompile_sha_compress {
    PICO_FFI
    RustError::by_value cuda_precompile_sha256_compress_generate_extra_record_and_main(
      const ShaCompressFfiEvent* events,
      size_t events_len,
      size_t event_size,
      field_t* trace,
      size_t total_rows,
      size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(
        events, events_len, event_size, trace, total_rows, num_cols, byte_trace, stream);
    } // cuda_precompile_sha256_compress_generate_extra_record_and_main
    PICO_FFI
    RustError::by_value cuda_precompile_sha256_compress_control_generate_extra_record_and_main(
      const ShaCompressFfiEvent* events,
      size_t events_len,
      field_t* trace,
      size_t total_rows,
      size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_control_compress_extra_record_and_main(events, events_len, trace, total_rows, num_cols, byte_trace, stream);
    } // cuda_precompile_sha256_compress_control_generate_extra_record_and_main
  } // namespace precompile_sha_compress

  namespace precompile_sha_extend {
    PICO_FFI
    RustError::by_value cuda_precompile_sha256_extend_generate_extra_record_and_main(
      const ShaExtendFfiEvent* events,
      size_t events_len,
      field_t* trace,
      size_t total_rows,
      size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(events, events_len, trace, total_rows, num_cols, byte_trace, stream);
    } // cuda_precompile_sha256_extend_generate_main

    PICO_FFI
    RustError::by_value cuda_precompile_sha256_extend_control_generate_extra_record_and_main(
      const ShaExtendFfiEvent* events,
      size_t events_len,
      field_t* trace,
      size_t total_rows,
      size_t num_cols,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_control_extra_record_and_main(events, events_len, trace, total_rows, num_cols, byte_trace, stream);
    } // cuda_precompile_sha256_extend_control_generate_extra_record_and_main
  } // namespace precompile_sha_extend

  namespace precompile_fp2_add_sub_bn254 {
    PICO_FFI
    RustError::by_value cuda_precompile_fp2_add_sub_bn254_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const Fp2AddSubEvent_t* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    } // cuda_precompile_precompile_fp2_add_sub_bn254_generate_extra_record_and_main
  } // namespace precompile_fp2_add_sub_bn254

  namespace precompile_fp2_add_sub_bls12381 {
    PICO_FFI
    RustError::by_value cuda_precompile_fp2_add_sub_bls12381_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const Fp2AddSubEvent_t* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    } // cuda_precompile_precompile_fp2_add_sub_bls12381_generate_extra_record_and_main
  } // namespace precompile_fp2_add_sub_bls12381

  namespace precompile_fp2_mul_bn254 {
    PICO_FFI
    RustError::by_value cuda_precompile_fp2_mul_bn254_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const Fp2MulEvent_t* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    } // cuda_precompile_precompile_fp2_mul_bn254_generate_extra_record_and_main
  } // namespace precompile_fp2_mul_bn254

  namespace precompile_fp2_mul_bls12381 {
    PICO_FFI
    RustError::by_value cuda_precompile_fp2_mul_bls12381_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const Fp2MulEvent_t* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    } // cuda_precompile_precompile_fp2_mul_bls12381_generate_extra_record_and_main
  } // namespace precompile_fp2_mul_bls12381

  namespace precompile_fp_op_bls381 {
    PICO_FFI
    RustError::by_value cuda_precompile_fp_op_bls381_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const FpEvent_t* events,
      field_t* trace,
      field_t* dummy_row,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, dummy_row, byte_trace, stream);
    } // cuda_precompile_fp_op_bls381_generate_extra_record_and_main
  } // namespace precompile_fp_op_bls381

  namespace precompile_fp_op_bn254 {
    PICO_FFI
    RustError::by_value cuda_precompile_fp_op_bn254_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const FpEvent_t* events,
      field_t* trace,
      field_t* dummy_row,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, dummy_row, byte_trace, stream);
    } // cuda_precompile_fp_op_bn254_generate_extra_record_and_main
  } // namespace precompile_fp_op_bn254

  namespace precompile_fp_op_secp256k1 {
    PICO_FFI
    RustError::by_value cuda_precompile_fp_op_secp256k1_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const FpEvent_t* events,
      field_t* trace,
      field_t* dummy_row,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, dummy_row, byte_trace, stream);
    } // cuda_precompile_fp_op_secp256k1_generate_extra_record_and_main
  } // namespace precompile_fp_op_secp256k1

} // namespace pico_gpu
