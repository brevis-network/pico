// The FFI entries of the mul, bitwise, shift-left and shift-right trace builders that read the
// execution history, declared to Rust in gpu-api/src/chips/history_bitwise_mul_shift.rs. `history`
// is the host's copy of the launch arguments and `layout` the layout it was built for, so a Rust
// side and a kernel library of two layouts fail here rather than misread the fill. Included from
// chips_group1.cu alone.
#pragma once

#include "field/ff_config.hpp"
#include "tracegen/common/prelude.cuh"
#include "tracegen/riscv/history_bitwise_mul_shift.cuh"

namespace pico_gpu {
  namespace mul_history {
    PICO_FFI
    RustError::by_value cuda_mul_generate_extra_record_and_main_history(
      const history::HistoryArgs* args,
      uint32_t layout,
      size_t num_cols,
      size_t trace_size,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      if (layout != history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main(*args, num_cols, trace_size, trace, byte_trace, stream);
    }
  } // namespace mul_history

  namespace bitwise_history {
    PICO_FFI
    RustError::by_value cuda_bitwise_generate_extra_record_and_main_history(
      const history::HistoryArgs* args,
      uint32_t layout,
      size_t num_cols,
      size_t trace_size,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      if (layout != history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main(*args, num_cols, trace_size, trace, byte_trace, stream);
    }
  } // namespace bitwise_history

  namespace sll_history {
    PICO_FFI
    RustError::by_value cuda_sll_generate_extra_record_and_main_history(
      const history::HistoryArgs* args,
      uint32_t layout,
      size_t num_cols,
      size_t trace_size,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      if (layout != history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main(*args, num_cols, trace_size, trace, byte_trace, stream);
    }
  } // namespace sll_history

  namespace sr_history {
    PICO_FFI
    RustError::by_value cuda_sr_generate_extra_record_and_main_history(
      const history::HistoryArgs* args,
      uint32_t layout,
      size_t num_cols,
      size_t trace_size,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      if (layout != history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main(*args, num_cols, trace_size, trace, byte_trace, stream);
    }
  } // namespace sr_history
} // namespace pico_gpu
