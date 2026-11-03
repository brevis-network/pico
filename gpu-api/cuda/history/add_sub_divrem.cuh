// The FFI entries of the add, addw, sub, subw and div/rem trace builders that read the execution
// history, declared to Rust in gpu-api/src/chips/history_add_sub_divrem.rs. `args` is the host's
// copy of the launch arguments and `layout` the layout it was built for, so a Rust side and a
// kernel library of two layouts fail here rather than misread the fill. Div/rem appends the ADD rows
// it derives to `derived`, `capacity` rows the host allocated from the fill's descriptor, and the add
// chip reads them from there after its own. Included from chips_group1.cu alone.
#pragma once

#include "field/ff_config.hpp"
#include "tracegen/common/prelude.cuh"
#include "tracegen/riscv/history_add_sub_divrem.cuh"

namespace pico_gpu {
  namespace add_history {
    PICO_FFI
    RustError::by_value cuda_add_generate_extra_record_and_main_history(
      const history::HistoryArgs* args,
      uint32_t layout,
      size_t num_cols,
      size_t trace_size,
      field_t* trace,
      field_t* byte_trace,
      const AluEventU64* derived,
      size_t capacity,
      cudaStream_t stream)
    {
      if (layout != history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main(*args, num_cols, trace_size, trace, byte_trace, derived, capacity, stream);
    }
  } // namespace add_history

  namespace addw_history {
    PICO_FFI
    RustError::by_value cuda_addw_generate_extra_record_and_main_history(
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
  } // namespace addw_history

  namespace sub_history {
    PICO_FFI
    RustError::by_value cuda_sub_generate_extra_record_and_main_history(
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
  } // namespace sub_history

  namespace subw_history {
    PICO_FFI
    RustError::by_value cuda_subw_generate_extra_record_and_main_history(
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
  } // namespace subw_history

  namespace divrem_history {
    PICO_FFI
    RustError::by_value cuda_divrem_generate_extra_record_and_main_history(
      const history::HistoryArgs* args,
      uint32_t layout,
      size_t num_cols,
      size_t trace_size,
      field_t* trace,
      field_t* byte_trace,
      AluEventU64* derived,
      size_t capacity,
      uint32_t* appended,
      cudaStream_t stream)
    {
      if (layout != history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main(
        *args, num_cols, trace_size, trace, byte_trace, derived, capacity, appended, stream);
    }
  } // namespace divrem_history
} // namespace pico_gpu
