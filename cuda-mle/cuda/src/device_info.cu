#include <cstdint>
#include <cuda_runtime.h>
#include <cuda_runtime_api.h>
#include <driver_types.h>

// Writes the streaming-multiprocessor count of GPU `ordinal` to *sm_count_out.
// Returns 0 on success or the cudaError_t value as an int.
extern "C" int _cuda_get_sm_count(uint32_t ordinal, uint32_t *sm_count_out) {
    int n_sms = 0;
    cudaError_t status = cudaDeviceGetAttribute(
        &n_sms, cudaDevAttrMultiProcessorCount, static_cast<int>(ordinal)
    );
    if (status != cudaSuccess) {
        return static_cast<int>(status);
    }
    *sm_count_out = static_cast<uint32_t>(n_sms);
    return 0;
}
