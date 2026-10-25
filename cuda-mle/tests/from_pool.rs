//! Exercises the external-pool allocation path (`cudaMallocFromPoolAsync`) end to end:
//! route `d_malloc` through the device's *default* CUDA memory pool via `set_external_pool`,
//! then run the same NTT roundtrip as `ntt_roundtrip.rs` (alloc → kernel → free) and verify.
//!
//! This proves the new extern signature + routing + pool-free work on a real GPU without
//! depending on pico's pool (which is wired up in S2).

use cuda_mle::{
    ntt_field::GpuNttField,
    runtime::{
        copy::{MemCopyD2H, MemCopyH2D},
        d_buffer::DeviceBuffer,
        memory_manager::{device_default_mem_pool, set_external_pool},
    },
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::KoalaBear as F;

#[test]
fn from_pool_alloc_roundtrip() {
    // Under CUDA_VISIBLE_DEVICES pinning the visible device is ordinal 0.
    let dev = 0;
    let pool = device_default_mem_pool(dev).expect("get default mem pool");
    assert!(!pool.is_null(), "default mem pool handle is null");
    unsafe { set_external_pool(dev, pool).expect("set external pool") };

    const LOG_N: u32 = 20;
    let n = 1usize << LOG_N;
    let mut host = Vec::<F>::with_capacity(n);
    for i in 0..n {
        host.push(F::from_usize(i));
    }

    // These allocations go through cudaMallocFromPoolAsync now.
    let mut device = DeviceBuffer::<F>::with_capacity(n);
    host.copy_to(&mut device).expect("host->device copy failed");

    F::batch_ntt(&device, LOG_N, 0, 1, true, false);
    F::batch_ntt(&device, LOG_N, 0, 1, true, true);

    let output = device.to_host().expect("device->host copy failed");
    for (i, got) in output.iter().enumerate() {
        assert_eq!(*got, host[i], "mismatch at index {}", i);
    }
    drop(device); // frees back into the pool via cudaFreeAsync

    // Clear the routing (back to cudaMallocAsync) for hygiene.
    unsafe { set_external_pool(dev, std::ptr::null_mut()).expect("clear external pool") };
}
