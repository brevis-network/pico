// The FFI entries of the ecall and RISC-V syscall trace builders that read the execution history,
// declared to Rust in gpu-api/src/chips/history_ecall_syscall.rs. `args` is the host's copy of
// the launch arguments and `layout` the layout it was built for, so a Rust side and a kernel
// library of two layouts fail here rather than misread the fill. The syscall entry writes one
// global event per row into the `global_slots` slots the host reserved from
// `global_events_start_index` on. Included from chips_group2.cu alone.
#pragma once

#include "field/ff_config.hpp"
#include "tracegen/common/prelude.cuh"
#include "tracegen/riscv/history_ecall_syscall.cuh"

namespace pico_gpu {
  namespace ecall_history {
    PICO_FFI
    RustError::by_value cuda_ecall_generate_extra_record_and_main_history(
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
  } // namespace ecall_history

  namespace syscall_history {
    PICO_FFI
    RustError::by_value cuda_syscall_generate_extra_record_and_main_history(
      const history::HistoryArgs* args,
      uint32_t layout,
      size_t num_cols,
      size_t trace_size,
      field_t* trace,
      field_t* byte_trace,
      GlobalInteractionEvent* global_events,
      size_t global_events_start_index,
      size_t global_slots,
      cudaStream_t stream)
    {
      if (layout != history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main(
        *args, num_cols, trace_size, trace, byte_trace, global_events, global_events_start_index, global_slots,
        stream);
    }
  } // namespace syscall_history
} // namespace pico_gpu
