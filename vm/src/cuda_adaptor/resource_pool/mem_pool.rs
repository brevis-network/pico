// Govern GPU's Memory
use cudart::{
    device::{get_device_count, set_device},
    memory_pools::{CudaMemPoolAttributeU64, CudaOwnedMemPool, DevicePoolAllocation},
    stream::CudaStream,
};
use cudart_sys::{
    CudaMemAllocationHandleType, CudaMemAllocationType, CudaMemLocation, CudaMemLocationType,
    CudaMemPoolProperties,
};
use std::{
    env,
    sync::{Mutex, OnceLock},
};

// deault memory pool reserved size (29G for RTX 5090)
const DEFAULT_MEM_POOL_RESERVE_SIZE: usize = 29_000_000_000;

/// The pool's `maxSize`: the ceiling on the virtual address range it may spread over. With the
/// CUDA default (0), that range is about twice the card's memory, 62.7 GiB on a 32 GB card, and a
/// long run scatters live blocks across all of it. A large request then finds no hole big enough
/// while the driver still has the memory free -- a 16 GiB GKR buffer failed with 19.3 GiB free --
/// and neither a trim nor a wait changes the layout. Address space costs no memory, so the ceiling
/// sits far above any card. `MEM_POOL_MAX_SIZE` (bytes) overrides it; 0 restores the default.
const DEFAULT_MEM_POOL_MAX_SIZE: usize = 1 << 40;

/// A pool on `device_id` with pinned device memory and the address ceiling above: what
/// `CudaOwnedMemPool::create_for_device` builds, plus `maxSize`.
fn create_device_pool(device_id: usize, max_size: usize) -> CudaOwnedMemPool {
    let props = CudaMemPoolProperties {
        allocType: CudaMemAllocationType::Pinned,
        handleTypes: CudaMemAllocationHandleType::None,
        location: device_location(device_id),
        maxSize: max_size,
        ..Default::default()
    };
    CudaOwnedMemPool::create(&props).unwrap_or_else(|e| {
        panic!("cannot create the memory pool for card {device_id} (maxSize {max_size}): {e:?}")
    })
}

/// `device_id` as a `cudaMemLocation`. Its `id` is a plain field in the CUDA 12 bindings and sits
/// in an anonymous union in CUDA 13's (the `cuda_13` cfg, set by `vm/build.rs`), as era-cuda's own
/// `make_mem_location` has it.
#[cfg(not(cuda_13))]
fn device_location(device_id: usize) -> CudaMemLocation {
    CudaMemLocation {
        type_: CudaMemLocationType::Device,
        id: device_id as i32,
    }
}

#[cfg(cuda_13)]
fn device_location(device_id: usize) -> CudaMemLocation {
    CudaMemLocation {
        type_: CudaMemLocationType::Device,
        __bindgen_anon_1: cudart_sys::cudaMemLocation__bindgen_ty_1 {
            id: device_id as i32,
        },
    }
}

#[derive(Debug)]
// pub struct SyncMemPool(pub Mutex<CudaOwnedMemPool>);
pub struct SyncMemPool(pub CudaOwnedMemPool);
unsafe impl Sync for SyncMemPool {}
unsafe impl Send for SyncMemPool {}
static GLOBAL_POOL: OnceLock<Vec<OnceLock<SyncMemPool>>> = OnceLock::new();

pub fn create_ctx(device_id: usize) {
    let pools = GLOBAL_POOL.get_or_init(|| {
        let count = get_device_count().unwrap() as usize;
        (0..count).map(|_| OnceLock::new()).collect()
    });

    if device_id >= pools.len() {
        panic!(
            "Device ID {} exceeds available devices ({})",
            device_id,
            pools.len()
        );
    }
    pools[device_id].get_or_init(|| {
        set_device(device_id as _).unwrap();
        let max_size = env::var("MEM_POOL_MAX_SIZE")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(DEFAULT_MEM_POOL_MAX_SIZE);
        let mem_pool = create_device_pool(device_id, max_size);
        tracing::info!(
            target: "bench",
            "MLE pool: card {device_id} memory pool maxSize={max_size}{}",
            if max_size == 0 { " (CUDA default)" } else { "" }
        );
        mem_pool
            .set_attribute_value(CudaMemPoolAttributeU64::AttrReleaseThreshold, u64::MAX)
            .unwrap();

        {
            let temp_stream = CudaStream::create().unwrap();
            let reserve_size = env::var("MEM_POOL_RESERVE_SIZE")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(DEFAULT_MEM_POOL_RESERVE_SIZE);
            if let Ok(reserve_alloc) = DevicePoolAllocation::<u8>::alloc_from_pool_async(
                reserve_size,
                &mem_pool,
                &temp_stream,
            ) {
                temp_stream.synchronize().unwrap();
                drop(reserve_alloc);
            };
            // temp_stream destroyed here automatically
        }

        SyncMemPool(mem_pool)
    });
}
pub fn get_global_mem_pool(device_id: usize) -> &'static SyncMemPool {
    let pools = GLOBAL_POOL
        .get()
        .unwrap_or_else(|| panic!("Global pool not initialized"));
    let pool = pools
        .get(device_id)
        .unwrap_or_else(|| panic!("Invalid device ID: {}", device_id))
        .get()
        .unwrap_or_else(|| panic!("Memory pool for device {} not initialized", device_id));

    pool
}

//
use cudart::memory::{CudaHostAllocFlags, HostAllocation};
use p3_koala_bear::KoalaBear;
const PING_PONG_BUFFER_SIZE: usize = 1 << 20;

static BUFFERS_FAST_H2D: OnceLock<Vec<OnceLock<Mutex<HostAllocation<KoalaBear>>>>> =
    OnceLock::new();
pub fn get_buffer(device_id: usize) -> &'static Mutex<HostAllocation<KoalaBear>> {
    let buffers = BUFFERS_FAST_H2D.get_or_init(|| {
        let device_count = get_device_count().unwrap() as usize;
        (0..device_count).map(|_| OnceLock::new()).collect()
    });

    if device_id >= buffers.len() {
        panic!(
            "Device ID {} exceeds available devices ({})",
            device_id,
            buffers.len()
        );
    }
    buffers[device_id].get_or_init(|| {
        set_device(device_id as i32).unwrap();

        // Named for the host: pinned host memory fails with the same CUDA status as a card.
        let alloc = HostAllocation::alloc(2 * PING_PONG_BUFFER_SIZE, CudaHostAllocFlags::DEFAULT)
            .unwrap_or_else(|e| panic!("pinned host allocation failed: {e:?}"));

        Mutex::new(alloc)
    })
}
