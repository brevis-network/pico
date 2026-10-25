// CPU, ALU, Global, MemoryReadWrite, Riscv_Poseidon2
#include "tracegen/recursion/alu_base.cuh"
#include "tracegen/recursion/alu_ext.cuh"
#include "tracegen/recursion/assert_zero_ext.cuh"
#include "tracegen/recursion/binary_fold_step.cuh"
#include "tracegen/recursion/digest_select.cuh"
#include "tracegen/recursion/exp_bits_len.cuh"
#include "tracegen/recursion/ext_dot_product.cuh"
#include "tracegen/recursion/frac_fold.cuh"
#include "tracegen/recursion/gkr_sumcheck_round.cuh"
#include "tracegen/recursion/horner_eval.cuh"
#include "tracegen/recursion/lagrange_eval_d2.cuh"
#include "tracegen/recursion/mle_open.cuh"
#include "tracegen/recursion/pack_block.cuh"
#include "tracegen/recursion/poseidon2_packed.cuh"
#include "tracegen/recursion/univariate_fold.cuh"
#include "tracegen/recursion/unpack_block.cuh"
#include "tracegen/riscv/program.cuh"
#include "tracegen/riscv/add_sub.cuh"
#include "tracegen/riscv/bitwise.cuh"
#include "tracegen/riscv/cpu.cuh"
#include "tracegen/riscv/divrem.cuh"
#include "tracegen/riscv/lt.cuh"
#include "tracegen/riscv/mul.cuh"
#include "tracegen/riscv/sll.cuh"
#include "tracegen/riscv/sr.cuh"

// Global
#include "tracegen/common/global_accumulation.cuh"
#include "tracegen/common/global_interaction.cuh"
#include "tracegen/riscv/riscv_global.cuh"

// Memory_read_write
#include "tracegen/riscv/memory_read_write.cuh"

// Packed-event (MLE_PACKED_EVENTS=1) trace-gen kernels
#include "tracegen/riscv/packed_tracegen.cuh"

// Riscv_Poseidon2
#include "tracegen/riscv/riscv_poseidon2.cuh"

#include "tracegen/common/selectors_on_coset.cuh"

namespace pico_gpu {


  namespace program_preprocess_u64 {
    PICO_FFI
    RustError::by_value cuda_riscv_program_generate_preprocessed_u64(
      const InstructionU64* instrs,
      const size_t num_instrs,
      const size_t padded_num_rows,
      const uint64_t pc_base,
      field_t* trace,
      const size_t num_cols,
      cudaStream_t stream)
    {
      return generate_preprocessed(
        instrs, num_instrs, padded_num_rows, pc_base, trace, num_cols, stream);
    }
  } // namespace program_preprocess_u64

  namespace program_u64 {
    PICO_FFI
    RustError::by_value cuda_riscv_program_generate_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      uint64_t pc_base,
      const FfiCpuEventU64* events,
      field_t* trace,
      cudaStream_t stream,
      size_t num_instrs)
    {
      return generate_main(num_cols, event_size, trace_size, pc_base, events, trace, stream, num_instrs);
    } // cuda_riscv_program_generate_main_u64
  } // namespace program_u64

  namespace alu_base {
    PICO_FFI
    RustError::by_value cuda_alu_base_generate_preprocessed(
      const BaseAluInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_alu_base_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_alu_base_generate_main(
      const BaseAluEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_alu_base_generate_main
  } // namespace alu_base

  namespace alu_ext {
    PICO_FFI
    RustError::by_value cuda_alu_ext_generate_preprocessed(
      const ExtAluInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_alu_ext_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_alu_ext_generate_main(
      const ExtAluEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_alu_ext_generate_main
  } // namespace alu_ext

  namespace assert_zero_ext {
    PICO_FFI
    RustError::by_value cuda_assert_zero_ext_generate_preprocessed(
      const AssertZeroExtInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_assert_zero_ext_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_assert_zero_ext_generate_main(
      const AssertZeroExtEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_assert_zero_ext_generate_main
  } // namespace assert_zero_ext

  namespace mle_open {
    PICO_FFI
    RustError::by_value cuda_mle_open_generate_preprocessed(
      const MleOpenInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_mle_open_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_mle_open_generate_main(
      const MleOpenEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_mle_open_generate_main
  } // namespace mle_open

  namespace frac_fold {
    PICO_FFI
    RustError::by_value cuda_frac_fold_generate_preprocessed(
      const FracFoldInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_frac_fold_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_frac_fold_generate_main(
      const FracFoldEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_frac_fold_generate_main
  } // namespace frac_fold

  namespace univariate_fold {
    PICO_FFI
    RustError::by_value cuda_univariate_fold_generate_preprocessed(
      const UnivariateFoldInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_univariate_fold_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_univariate_fold_generate_main(
      const UnivariateFoldFlatEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, uint32_t w, cudaStream_t stream)
    {
      // `w` is passed as the canonical u32 of the binomial extension constant; reconstruct the
      // field element at the FFI boundary so the Rust side never depends on the field's internal repr.
      return generate_main(events, events_len, trace, num_cols, field_t::from_canonical_u32(w), stream);
    } // cuda_univariate_fold_generate_main
  } // namespace univariate_fold

  namespace unpack_block {
    PICO_FFI
    RustError::by_value cuda_unpack_block_generate_preprocessed(
      const UnpackBlockInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_unpack_block_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_unpack_block_generate_main(
      const UnpackBlockEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_unpack_block_generate_main
  } // namespace unpack_block

  namespace lagrange_eval_d2 {
    PICO_FFI
    RustError::by_value cuda_lagrange_eval_d2_generate_preprocessed(
      const LagrangeEvalD2Instr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_lagrange_eval_d2_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_lagrange_eval_d2_generate_main(
      const LagrangeEvalD2Event<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_lagrange_eval_d2_generate_main
  } // namespace lagrange_eval_d2

  namespace pack_block {
    PICO_FFI
    RustError::by_value cuda_pack_block_generate_preprocessed(
      const PackBlockInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_pack_block_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_pack_block_generate_main(
      const PackBlockEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_pack_block_generate_main
  } // namespace pack_block

  namespace digest_select {
    PICO_FFI
    RustError::by_value cuda_digest_select_generate_preprocessed(
      const DigestSelectInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_digest_select_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_digest_select_generate_main(
      const DigestSelectEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_digest_select_generate_main
  } // namespace digest_select

  namespace ext_dot_product {
    PICO_FFI
    RustError::by_value cuda_ext_dot_product_generate_preprocessed(
      const ExtDotProductPreprocMeta<field_t>* metas, size_t num_instrs,
      const field_t* mu_addrs_flat, const field_t* val_addrs_flat,
      field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(metas, num_instrs, mu_addrs_flat, val_addrs_flat, trace, num_cols, stream);
    } // cuda_ext_dot_product_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_ext_dot_product_generate_main(
      const ExtDotProductEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, stream);
    } // cuda_ext_dot_product_generate_main
  } // namespace ext_dot_product

  namespace exp_bits_len {
    PICO_FFI
    RustError::by_value cuda_exp_bits_len_generate_preprocessed(
      const ExpBitsLenPreprocMeta<field_t>* metas, size_t num_instrs,
      const RecursionMemoryAccessCols<field_t>* bit_outs_flat,
      field_t* trace, size_t num_cols, size_t num_real_rows, cudaStream_t stream)
    {
      return generate_preprocessed(metas, num_instrs, bit_outs_flat, trace, num_cols, num_real_rows, stream);
    } // cuda_exp_bits_len_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_exp_bits_len_generate_main(
      const ExpBitsLenFlatEvent<field_t>* events, size_t num_events,
      field_t* trace, size_t num_cols, size_t num_rows, cudaStream_t stream)
    {
      return generate_main(events, num_events, trace, num_cols, num_rows, stream);
    } // cuda_exp_bits_len_generate_main
  } // namespace exp_bits_len

  namespace gkr_sumcheck_round {
    PICO_FFI
    RustError::by_value cuda_gkr_sumcheck_round_generate_preprocessed(
      const GkrSumcheckRoundInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_gkr_sumcheck_round_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_gkr_sumcheck_round_generate_main(
      const GkrSumcheckRoundEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, uint32_t w, cudaStream_t stream)
    {
      // `w` is the canonical u32 of the binomial extension constant; rebuilt at the FFI boundary.
      return generate_main(events, events_len, trace, num_cols, field_t::from_canonical_u32(w), stream);
    } // cuda_gkr_sumcheck_round_generate_main
  } // namespace gkr_sumcheck_round

  namespace horner_eval {
    PICO_FFI
    RustError::by_value cuda_horner_eval_generate_preprocessed(
      const HornerEvalPreprocMeta<field_t>* metas, size_t num_instrs,
      const field_t* coeff_addrs_flat, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(metas, num_instrs, coeff_addrs_flat, trace, num_cols, stream);
    } // cuda_horner_eval_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_horner_eval_generate_main(
      const HornerEvalEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, uint32_t w, cudaStream_t stream)
    {
      return generate_main(events, events_len, trace, num_cols, field_t::from_canonical_u32(w), stream);
    } // cuda_horner_eval_generate_main
  } // namespace horner_eval

  namespace binary_fold_step {
    PICO_FFI
    RustError::by_value cuda_binary_fold_step_generate_preprocessed(
      const BinaryFoldStepInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_binary_fold_step_generate_preprocessed
    PICO_FFI
    RustError::by_value cuda_binary_fold_step_generate_main(
      const BinaryFoldStepEvent<field_t>* events, size_t events_len, field_t* trace, size_t num_cols, uint32_t inv2, cudaStream_t stream)
    {
      // `inv2` is the canonical u32 of the field element 1/2; rebuilt at the FFI boundary.
      return generate_main(events, events_len, trace, num_cols, field_t::from_canonical_u32(inv2), stream);
    } // cuda_binary_fold_step_generate_main
  } // namespace binary_fold_step

  namespace poseidon2_packed {
    // Main trace reuses the recursion poseidon2 kernel (cuda_recursion_poseidon2_generate_main);
    // only the packed preprocessed layout is provided here.
    PICO_FFI
    RustError::by_value cuda_poseidon2_packed_generate_preprocessed(
      const Poseidon2PackedInstr<field_t>* instrs, size_t num_instrs, field_t* trace, size_t num_cols, cudaStream_t stream)
    {
      return generate_preprocessed(instrs, num_instrs, trace, num_cols, stream);
    } // cuda_poseidon2_packed_generate_preprocessed
  } // namespace poseidon2_packed

  namespace add_u64 {
    PICO_FFI
    RustError::by_value cuda_add_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace add_u64

  namespace addw_u64 {
    PICO_FFI
    RustError::by_value cuda_addw_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace addw_u64

  namespace sub_u64 {
    PICO_FFI
    RustError::by_value cuda_sub_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace sub_u64

  namespace subw_u64 {
    PICO_FFI
    RustError::by_value cuda_subw_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace subw_u64

  namespace bitwise_u64 {
    PICO_FFI
    RustError::by_value cuda_bitwise_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return bitwise_u64::generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace bitwise_u64

  namespace divrem {
    PICO_FFI
    RustError::by_value cuda_divrem_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      cudaStream_t stream,
      const DivremExtraEventIndices* extra_event_indices,
      field_t* byte_trace,
      AluEventU64* alu_add_sub_events,
      size_t alu_add_sub_events_start_index)
    {
      return generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, stream, extra_event_indices, byte_trace, alu_add_sub_events,
        alu_add_sub_events_start_index);
    }
  } // namespace divrem

  namespace lt_u64 {
    PICO_FFI
    RustError::by_value cuda_lt_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return generate_extra_record_and_main(num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace lt_u64

  namespace mul_u64 {
    PICO_FFI
    RustError::by_value cuda_mul_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return pico_gpu::mul_u64::generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace mul_u64

  namespace sll_u64 {
    PICO_FFI
    RustError::by_value cuda_sll_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return pico_gpu::sll_u64::generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace sll_u64

  namespace sr_u64 {
    PICO_FFI
    RustError::by_value cuda_sr_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      return pico_gpu::sr_u64::generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace sr_u64

  namespace cpu_u64 {
    PICO_FFI
    RustError::by_value cuda_cpu_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      const FfiCpuEventU64* events,
      field_t* trace,
      cudaStream_t stream,
      const CpuExtraEventIndices* extra_event_indices,
      field_t* byte_trace,
      AluEventU64* alu_add_sub_events,
      size_t alu_add_sub_events_start_index,
      AluEventU64* alu_lt_events,
      size_t alu_lt_events_start_index)
    {
      return generate_extra_record_and_main(
        num_cols, event_size, events, trace, stream, extra_event_indices, byte_trace,
        alu_add_sub_events, alu_add_sub_events_start_index,
        alu_lt_events, alu_lt_events_start_index);
    }

    PICO_FFI
    RustError::by_value
    cuda_cpu_pad_trace_u64(size_t num_cols, size_t start_row, size_t end_row, field_t* trace, cudaStream_t stream)
    {
      return pad_trace(num_cols, start_row, end_row, trace, stream);
    }
  } // namespace cpu_u64

  namespace riscv_global {
    PICO_FFI
    RustError::by_value cuda_riscv_global_generate_extra_record_and_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const GlobalInteractionEvent* events,
      field_t* trace,
      cudaStream_t stream,
      field_t* byte_trace,
      Poseidon2Event* poseidon2_events,
      size_t poseidon2_events_start_index,
      const field_t* round_constants)
    {
      return generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, trace, stream, byte_trace, poseidon2_events,
        poseidon2_events_start_index, round_constants);
    }
  } // namespace riscv_global

  namespace memory_read_write_u64 {
    PICO_FFI
    RustError::by_value cuda_memory_read_write_generate_extra_record_and_main_u64(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const FfiCpuEventU64* events,
      const size_t* event_indices,
      field_t* trace,
      cudaStream_t stream,
      field_t* byte_trace)
    {
      return generate_extra_record_and_main(
        num_cols, event_size, trace_size, events, event_indices, trace, stream, byte_trace);
    }
  } // namespace memory_read_write_u64

  namespace riscv_poseidon2 {
    PICO_FFI
    RustError::by_value cuda_riscv_poseidon2_generate_main(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const Poseidon2Event* events,
      field_t* trace,
      field_t* dummy_row,
      const field_t* round_constants,
      cudaStream_t stream)
    {
      return generate_main(
        num_cols, event_size, trace_size, events, trace, dummy_row, round_constants, stream);
    } // cuda_riscv_poseidon2_generate_main
  } // namespace riscv_poseidon2

  PICO_FFI
  RustError::by_value cuda_selectors_on_coset(
    const field_t* coset_constants,
    size_t xs_len,
    size_t evals_len,
    const field_t* evals,
    field_t* is_first_row,
    field_t* is_last_row,
    field_t* is_transition,
    field_t* inv_zeroifier,
    cudaStream_t stream)
  {
    return selectors_on_coset_gpu(
      coset_constants, xs_len, evals_len, evals, is_first_row, is_last_row, is_transition, inv_zeroifier, stream);
  }

  namespace alu_common {
    PICO_FFI
    RustError::by_value cuda_alu_partition_events(
      const AluEventU64* all_events,
      size_t total_count,
      AluEventU64* out_add,
      AluEventU64* out_sub,
      AluEventU64* out_addw,
      AluEventU64* out_subw,
      cudaStream_t stream)
    {
      return pico_gpu::add_sub_common::partition_events(
        all_events, total_count, out_add, out_sub, out_addw, out_subw, stream);
    }
  } // namespace alu_common


  // ─── Packed-event (MLE_PACKED_EVENTS=1) FFI entries ─────────────────────────────────────
  // New symbols only; every entry validates the format handshake so an unpaired
  // pico / pico-gpu deploy fails loudly instead of misreading bytes.

  namespace cpu_u64_packed {
    PICO_FFI
    RustError::by_value cuda_cpu_generate_extra_record_and_main_u64_packed(
      size_t num_cols,
      size_t event_size,
      const FfiCpuEventPacked* events,
      size_t chunk,
      field_t* trace,
      cudaStream_t stream,
      const CpuExtraEventIndices* extra_event_indices,
      field_t* byte_trace,
      AddSubEventPacked* alu_add_sub_events,
      size_t alu_add_sub_events_start_index,
      LtEventPacked* alu_lt_events,
      size_t alu_lt_events_start_index,
      size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main_packed(
        num_cols, event_size, events, (uint32_t)chunk, trace, stream, extra_event_indices,
        byte_trace, alu_add_sub_events, alu_add_sub_events_start_index,
        alu_lt_events, alu_lt_events_start_index);
    }
  } // namespace cpu_u64_packed

  namespace memory_read_write_u64_packed {
    PICO_FFI
    RustError::by_value cuda_memory_read_write_generate_extra_record_and_main_u64_packed(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const FfiCpuEventPacked* events,
      const FfiMemRecordPacked* mem_records,
      size_t chunk,
      const size_t* event_indices,
      field_t* trace,
      cudaStream_t stream,
      field_t* byte_trace,
      size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main_packed(
        num_cols, event_size, trace_size, events, mem_records, (uint32_t)chunk, event_indices,
        trace, stream, byte_trace);
    }
  } // namespace memory_read_write_u64_packed

  namespace lt_u64_packed {
    PICO_FFI
    RustError::by_value cuda_lt_generate_extra_record_and_main_u64_packed(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const LtEventPacked* events,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream,
      size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main_packed(
        num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace lt_u64_packed

  namespace add_u64_packed {
    PICO_FFI
    RustError::by_value cuda_add_generate_extra_record_and_main_packed(
      size_t num_cols, size_t event_size, size_t trace_size,
      const AddSubEventPacked* events, field_t* trace, field_t* byte_trace,
      cudaStream_t stream, size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main_packed(
        num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace add_u64_packed

  namespace addw_u64_packed {
    PICO_FFI
    RustError::by_value cuda_addw_generate_extra_record_and_main_packed(
      size_t num_cols, size_t event_size, size_t trace_size,
      const AddSubEventPacked* events, field_t* trace, field_t* byte_trace,
      cudaStream_t stream, size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main_packed(
        num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace addw_u64_packed

  namespace sub_u64_packed {
    PICO_FFI
    RustError::by_value cuda_sub_generate_extra_record_and_main_packed(
      size_t num_cols, size_t event_size, size_t trace_size,
      const AddSubEventPacked* events, field_t* trace, field_t* byte_trace,
      cudaStream_t stream, size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main_packed(
        num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace sub_u64_packed

  namespace subw_u64_packed {
    PICO_FFI
    RustError::by_value cuda_subw_generate_extra_record_and_main_packed(
      size_t num_cols, size_t event_size, size_t trace_size,
      const AddSubEventPacked* events, field_t* trace, field_t* byte_trace,
      cudaStream_t stream, size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main_packed(
        num_cols, event_size, trace_size, events, trace, byte_trace, stream);
    }
  } // namespace subw_u64_packed

  namespace divrem_packed {
    PICO_FFI
    RustError::by_value cuda_divrem_generate_extra_record_and_main_packed(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      const AluEventU64* events,
      field_t* trace,
      cudaStream_t stream,
      const DivremExtraEventIndices* extra_event_indices,
      field_t* byte_trace,
      AddSubEventPacked* alu_add_sub_events,
      size_t alu_add_sub_events_start_index,
      size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main_packed(
        num_cols, event_size, trace_size, events, trace, stream, extra_event_indices,
        byte_trace, alu_add_sub_events, alu_add_sub_events_start_index);
    }
  } // namespace divrem_packed

  namespace program_u64_packed {
    PICO_FFI
    RustError::by_value cuda_riscv_program_generate_main_u64_packed(
      size_t num_cols,
      size_t event_size,
      size_t trace_size,
      uint64_t pc_base,
      const FfiCpuEventPacked* events,
      field_t* trace,
      cudaStream_t stream,
      size_t num_instrs,
      size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return generate_main_packed(
        num_cols, event_size, trace_size, pc_base, events, trace, stream, num_instrs);
    }
  } // namespace program_u64_packed

  namespace alu_common_packed {
    PICO_FFI
    RustError::by_value cuda_alu_partition_events_packed(
      const AddSubEventPacked* all_events,
      size_t total_count,
      AddSubEventPacked* out_add,
      AddSubEventPacked* out_sub,
      AddSubEventPacked* out_addw,
      AddSubEventPacked* out_subw,
      cudaStream_t stream,
      size_t format_version)
    {
      if (format_version != PICO_PACKED_EVENT_FORMAT_V1) return RustError{cudaErrorInvalidValue};
      return pico_gpu::add_sub_common_packed::partition_events_packed(
        all_events, total_count, out_add, out_sub, out_addw, out_subw, stream);
    }
  } // namespace alu_common_packed

} // namespace pico_gpu
