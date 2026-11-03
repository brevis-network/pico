// The FFI entries of the CPU, program, memory read/write and less-than trace builders that read the
// execution history, declared to Rust in gpu-api/src/chips/history_cpu_memory_lt.rs. `args` is
// the host's copy of the launch arguments and `layout` the layout it was built for, so a Rust side
// and a kernel library of two layouts fail here rather than misread the fill. The CPU chip takes one
// call per slice, so that the host can make each slice's stream wait for that slice's copy alone,
// and one for its padding. `cuda_history_spin` holds a stream, for the tests that delay one producer
// of an ordering edge. Included from chips_group1.cu alone.
#pragma once

#include "field/ff_config.hpp"
#include "tracegen/common/prelude.cuh"
#include "tracegen/riscv/history_cpu_memory_lt.cuh"

namespace pico_gpu {
  namespace cpu_memory_lt_history {
    PICO_FFI
    RustError::by_value cuda_history_spin(uint64_t nanoseconds, cudaStream_t stream)
    {
      return spin(nanoseconds, stream);
    }
  } // namespace cpu_memory_lt_history

  namespace cpu_history {
    PICO_FFI
    RustError::by_value cuda_cpu_generate_extra_record_and_main_history(
      const history::HistoryArgs* args,
      uint32_t layout,
      uint32_t slice,
      uint32_t slices,
      size_t slice_steps,
      size_t num_cols,
      size_t trace_size,
      field_t* trace,
      field_t* byte_trace,
      cudaStream_t stream)
    {
      if (layout != history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
      return generate_extra_record_and_main(
        *args, slice, slices, slice_steps, num_cols, trace_size, trace, byte_trace, stream);
    }

    PICO_FFI
    RustError::by_value cuda_cpu_pad_trace_history(
      const history::HistoryArgs* args,
      uint32_t layout,
      size_t num_cols,
      size_t trace_size,
      field_t* trace,
      cudaStream_t stream)
    {
      if (layout != history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
      return pad_trace(*args, num_cols, trace_size, trace, stream);
    }
  } // namespace cpu_history

  namespace program_history {
    PICO_FFI
    RustError::by_value cuda_riscv_program_generate_main_history(
      const history::HistoryArgs* args,
      uint32_t layout,
      size_t num_cols,
      size_t trace_size,
      size_t instructions,
      field_t* trace,
      cudaStream_t stream)
    {
      if (layout != history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
      return generate_main(*args, num_cols, trace_size, instructions, trace, stream);
    }
  } // namespace program_history

  namespace memory_read_write_history {
    PICO_FFI
    RustError::by_value cuda_memory_read_write_generate_extra_record_and_main_history(
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
  } // namespace memory_read_write_history

  namespace lt_history {
    PICO_FFI
    RustError::by_value cuda_lt_generate_extra_record_and_main_history(
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
  } // namespace lt_history
} // namespace pico_gpu
