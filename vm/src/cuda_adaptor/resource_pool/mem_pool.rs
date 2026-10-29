// Govern GPU's Memory
use cudart::{
    device::{get_device_count, set_device},
    memory_pools::{CudaMemPoolAttributeU64, CudaOwnedMemPool, DevicePoolAllocation},
    stream::CudaStream,
};
use std::{
    env,
    sync::{Mutex, OnceLock},
};

// deault memory pool reserved size (29G for RTX 5090)
const DEFAULT_MEM_POOL_RESERVE_SIZE: usize = 29_000_000_000;

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
        let mem_pool = CudaOwnedMemPool::create_for_device(device_id as i32).unwrap();
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

        let alloc =
            HostAllocation::alloc(2 * PING_PONG_BUFFER_SIZE, CudaHostAllocFlags::DEFAULT).unwrap();

        Mutex::new(alloc)
    })
}
