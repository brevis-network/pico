use cudart::{
    device::{get_device_count, set_device},
    stream::CudaStream,
};
use std::sync::OnceLock;

#[derive(Debug)]
pub struct SyncStreamPool(pub CudaStream);
unsafe impl Sync for SyncStreamPool {}
unsafe impl Send for SyncStreamPool {}
static GLOBAL_POOL: OnceLock<Vec<OnceLock<SyncStreamPool>>> = OnceLock::new();

extern "C" {
    fn rustffi_check_layout();
}

pub fn create_stream(device_id: usize) {
    let pools = GLOBAL_POOL.get_or_init(|| {
        // Check DataStruct
        println!("Check CPU DATA STRUCT");
        crate::cuda_adaptor::check_layout();
        println!("Check GPU DATA STRUCT");
        unsafe {
            rustffi_check_layout();
        };

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
        let stream_pool = CudaStream::create().unwrap();
        SyncStreamPool(stream_pool)
    });
}
pub fn get_global_stream_pool(device_id: usize) -> &'static SyncStreamPool {
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
