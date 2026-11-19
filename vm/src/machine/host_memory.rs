//! This host's memory, and the low-memory defaults a small host runs with.

use std::sync::OnceLock;

/// Picks the host-memory tier, `low` or `high`, over the detected one.
pub const HOST_MEM_VAR: &str = "PICO_HOST_MEM";

/// Hosts with less memory than this, in decimal bytes (500 GB), or a container capped below it,
/// run the low-memory defaults. Above it the defaults stay tuned for throughput.
pub const LOW_MEMORY_HOST_BYTES: u64 = 500_000_000_000;

/// An embedded GPU prove's history slots (its event pool) on a low-memory host.
pub const LOW_MEMORY_EVENT_POOL: usize = 4;

/// Emulator memories in the pool on a low-memory host, in a `cuda` build.
pub const LOW_MEMORY_POOL_SIZE: usize = 4;

/// Replay workers a `cuda` build runs on a low-memory host when the caller states none.
pub const LOW_MEMORY_REPLAY_WORKERS: usize = 2;

/// Deferred records the emulation may run ahead of proving by on a low-memory host.
pub const LOW_MEMORY_DEFERRED_RECORDS: usize = 8;

/// This host's memory, or its container's limit where there is one; `0` when it cannot be read.
///
/// The container limit is the one at the cgroup mount's root. A limit set elsewhere (systemd's
/// `MemoryMax=`, Slurm's `--mem`, a parent cgroup, `numactl --membind`) is not seen: set
/// [`HOST_MEM_VAR`] there.
pub fn host_bytes() -> u64 {
    let mut sys = sysinfo::System::new();
    sys.refresh_memory();
    // sysinfo's `cgroup_limits` asserts a nonzero total, which an unreadable `/proc/meminfo` gives.
    if sys.total_memory() == 0 {
        return 0;
    }
    sys.cgroup_limits().map_or(sys.total_memory(), |limits| {
        limits.total_memory.min(sys.total_memory())
    })
}

/// The tier [`HOST_MEM_VAR`] picks: `Some(true)` for `low`, `Some(false)` for `high`, `None` when
/// unset. An embedded prove checks it up front, so a bad value is refused before anything runs.
pub fn host_mem_setting() -> Result<Option<bool>, String> {
    match std::env::var(HOST_MEM_VAR) {
        Err(_) => Ok(None),
        Ok(v) => match v.trim().to_lowercase().as_str() {
            "low" => Ok(Some(true)),
            "high" => Ok(Some(false)),
            _ => Err(format!("{HOST_MEM_VAR}={v}: expected `low` or `high`")),
        },
    }
}

/// Whether this host runs the low-memory defaults: [`HOST_MEM_VAR`] if set, else
/// [`host_bytes`] below [`LOW_MEMORY_HOST_BYTES`]. Read once per process. A variable that sets
/// one of the defaults itself (`MLE_DEFERRED_RECORDS`, `MEMORY_POOL_SIZE`, an explicit event pool
/// size) wins over either tier.
pub fn low_memory_host() -> bool {
    static LOW: OnceLock<bool> = OnceLock::new();
    *LOW.get_or_init(|| {
        let setting = host_mem_setting().unwrap_or_else(|e| {
            tracing::warn!("{e}; detecting the host-memory tier instead");
            None
        });
        let (low, source) = match setting {
            Some(low) => (low, HOST_MEM_VAR.to_string()),
            None => {
                let bytes = host_bytes();
                if bytes == 0 {
                    tracing::warn!("cannot read this host's memory; set {HOST_MEM_VAR}");
                }
                (
                    bytes < LOW_MEMORY_HOST_BYTES,
                    format!("{bytes} bytes detected"),
                )
            }
        };
        tracing::info!(
            "host-memory tier: {} ({source})",
            if low { "low" } else { "high" }
        );
        low
    })
}
