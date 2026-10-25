//! `ensure_default_pool_retains` must raise the release threshold of the **device default** pool,
//! on **every** device and idempotently. The `.cu` scratch allocators draw from that pool, so at
//! the driver's default threshold of 0 every scratch alloc/free pair round-trips physical memory
//! through the driver instead of being recycled.
//!
//! Enumerating the devices is the point of the test, not thoroughness: the defect being fixed was
//! that a single process-wide `static` raised one card and left the other N-1 at 0, so a test
//! pinned to device 0 passes just as well against the defect as against the fix.

use cuda_mle::runtime::memory_manager::{
    default_pool_release_threshold, ensure_default_pool_retains, visible_device_count,
};

#[test]
fn ensure_default_pool_retains_raises_the_threshold_on_every_device() {
    // `MLE_POOL_RETAIN=0` is the kill-switch; this test asserts the enabled behaviour.
    if std::env::var("MLE_POOL_RETAIN").is_ok_and(|v| v == "0") {
        eprintln!("MLE_POOL_RETAIN=0 set; skipping");
        return;
    }
    let devices = visible_device_count();
    assert!(devices > 0, "no CUDA device visible; cannot test the pool");

    for dev in 0..devices {
        assert!(
            ensure_default_pool_retains(dev),
            "raising the default pool's release threshold failed on device {dev} of {devices}"
        );
        let threshold = default_pool_release_threshold(dev)
            .unwrap_or_else(|e| panic!("reading device {dev}'s release threshold back: {e}"));
        // Not `== u64::MAX`: the driver is free to clamp or normalise a stored pool attribute,
        // and this test should fail only when the pool is not retaining. 1 TiB is far above any
        // scratch buffer the `.cu` allocators ask for, and far above the 0 the defect leaves.
        assert!(
            threshold >= 1 << 40,
            "device {dev} of {devices}: default pool kept a release threshold of {threshold}, \
             so its `.cu` scratch allocations still round-trip physical memory"
        );
        // Idempotent: a second call is a cached read, not a second driver write.
        assert!(ensure_default_pool_retains(dev));
    }
}
