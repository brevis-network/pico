// NVTX through the header-only NVTX3 API, so nothing is linked: CUDA 12.9 dropped
// libnvToolsExt. The calls are no-ops unless a tool (nsys) injects itself at runtime.
#include <nvtx3/nvToolsExt.h>

extern "C" int pico_nvtx_range_push(const char *message) { return nvtxRangePushA(message); }

extern "C" int pico_nvtx_range_pop() { return nvtxRangePop(); }
