// The FFI entry of the whole-fill checks of the execution history (history_validate.cuh), declared
// to Rust in gpu-api/src/chips/history_validate.rs. `args` is the host's copy of the launch
// arguments and `layout` the layout they were built for, so a Rust side and a kernel library of two
// layouts fail here rather than misread the fill. Its own translation unit: the kernel library's
// header carries nothing another one defines.
#include "tracegen/common/prelude.cuh"
#include "tracegen/riscv/history_validate.cuh"

PICO_FFI RustError::by_value
cuda_history_validate(const pico_gpu::history::HistoryArgs* args, uint32_t layout, cudaStream_t stream)
{
  if (layout != pico_gpu::history::HISTORY_LAYOUT) return RustError{cudaErrorInvalidValue};
  return pico_gpu::history_validate::validate(*args, stream);
}
