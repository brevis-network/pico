//! Minimal nvrtc + CUDA driver-API JIT harness for generated per-AIR kernels. Compiles a
//! self-contained CUDA source string (no host headers) to CUBIN at first use and caches the loaded
//! `CUfunction` per (source-hash, device), plus a cubin disk cache. Gated by the caller
//! (`G1_JIT=1`).

use std::{
    collections::HashMap,
    ffi::{c_void, CString},
    path::PathBuf,
    ptr,
    sync::Mutex,
};

use crate::runtime::error::CudaError;

#[allow(non_camel_case_types)]
type nvrtcProgram = *mut c_void;
#[allow(non_camel_case_types)]
type CUmodule = *mut c_void;
#[allow(non_camel_case_types)]
type CUfunction = *mut c_void;

extern "C" {
    fn nvrtcCreateProgram(
        prog: *mut nvrtcProgram,
        src: *const i8,
        name: *const i8,
        num_headers: i32,
        headers: *const *const i8,
        include_names: *const *const i8,
    ) -> i32;
    fn nvrtcCompileProgram(prog: nvrtcProgram, num_options: i32, options: *const *const i8) -> i32;
    fn nvrtcGetCUBINSize(prog: nvrtcProgram, size: *mut usize) -> i32;
    fn nvrtcGetCUBIN(prog: nvrtcProgram, cubin: *mut i8) -> i32;
    fn nvrtcGetProgramLogSize(prog: nvrtcProgram, size: *mut usize) -> i32;
    fn nvrtcGetProgramLog(prog: nvrtcProgram, log: *mut i8) -> i32;
    fn nvrtcDestroyProgram(prog: *mut nvrtcProgram) -> i32;

    fn cuModuleLoadData(module: *mut CUmodule, image: *const c_void) -> i32;
    fn cuModuleGetFunction(func: *mut CUfunction, module: CUmodule, name: *const i8) -> i32;
    fn cuLaunchKernel(
        f: CUfunction,
        grid_x: u32,
        grid_y: u32,
        grid_z: u32,
        block_x: u32,
        block_y: u32,
        block_z: u32,
        shared_bytes: u32,
        stream: *mut c_void,
        params: *mut *mut c_void,
        extra: *mut *mut c_void,
    ) -> i32;
}

/// `CU_STREAM_PER_THREAD`. The runtime-API kernels this one is interleaved with land here because
/// `cuda-mle`'s CUDA is compiled `--default-stream=per-thread` (`build.rs`); the driver API takes no
/// notice of that flag, so a JIT launch has to name the stream to end up in the same place.
const CU_STREAM_PER_THREAD: *mut c_void = 0x2 as *mut c_void;

/// Loaded JIT kernel handle. The module stays loaded for the process lifetime.
#[derive(Clone, Copy)]
pub struct JitKernel {
    func: CUfunction,
}
// CUfunction handles are usable from any thread once loaded on the device's primary context.
unsafe impl Send for JitKernel {}
unsafe impl Sync for JitKernel {}

/// Both caches are keyed by device id as well as source: a loaded `CUmodule`/`CUfunction` belongs
/// to the loading device's primary context, and launching one from another card fails hard
/// (`CUDA_ERROR_INVALID_HANDLE`-class). The nvrtc OUTPUT (the cubin disk cache) stays shared —
/// only loaded handles are per-card.
static KERNEL_CACHE: Mutex<Option<HashMap<(i32, u64, String), JitKernel>>> = Mutex::new(None);
/// Loaded modules by (device, source hash), so multiple kernels from one generated source load
/// once per card.
static MODULE_CACHE: Mutex<Option<HashMap<(i32, u64), usize>>> = Mutex::new(None);

/// Modules and kernel handles loaded on `device`. A module stays loaded for the process lifetime
/// and its device-side code sits outside every memory pool, so a count that climbs with blocks is
/// growth no pool trim can reach. Per device because the census reports it per card and both
/// caches are keyed by one.
pub fn jit_cache_len(device: i32) -> (usize, usize) {
    let modules = MODULE_CACHE
        .lock()
        .ok()
        .and_then(|c| {
            c.as_ref()
                .map(|m| m.keys().filter(|k| k.0 == device).count())
        })
        .unwrap_or(0);
    let kernels = KERNEL_CACHE
        .lock()
        .ok()
        .and_then(|c| {
            c.as_ref()
                .map(|m| m.keys().filter(|k| k.0 == device).count())
        })
        .unwrap_or(0);
    (modules, kernels)
}

fn source_hash(src: &str) -> u64 {
    // FxHash-style cheap hash; collisions only cost a recompile-mismatch, and sources
    // are fully deterministic per AIR, so a simple FNV-1a suffices.
    let mut h: u64 = 0xcbf29ce484222325;
    for b in src.as_bytes() {
        h ^= *b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

fn device_arch_flag() -> Result<String, CudaError> {
    use crate::runtime::context::get_device;
    let dev = get_device()?;
    let mut major = 0i32;
    let mut minor = 0i32;
    unsafe {
        // cudaDevAttrComputeCapabilityMajor = 75, Minor = 76
        crate::runtime::error::check(cudaDeviceGetAttribute(&mut major, 75, dev))?;
        crate::runtime::error::check(cudaDeviceGetAttribute(&mut minor, 76, dev))?;
    }
    // Real SM arch (not virtual `compute_`): nvrtc runs ptxas and emits CUBIN (machine code) via
    // nvrtcGetCUBIN, so module load takes a ready SASS image. The virtual-arch + PTX path let the
    // CUDA driver JIT PTX→SASS at `cuModuleLoadData`, which deadlocks under the prover's high thread
    // count.
    Ok(format!("--gpu-architecture=sm_{major}{minor}"))
}

extern "C" {
    fn cudaDeviceGetAttribute(value: *mut i32, attr: i32, device: i32) -> i32;
}

/// One nvrtc compilation at a time, process-wide. libnvrtc's internal threading intermittently
/// deadlocks (`nvrtcCompileProgram` parked on a futex) when several prover threads compile at once.
///
/// The guard covers all of `compile_module`, cubin-cache hit included. With the disk cache on (the
/// default, and what the runner sets) only the first card compiles and the rest take the read path,
/// so the extra scope is free; with the cache off it serialises every card's compile of the same
/// source, which is slow but is the behaviour the deadlock forces anyway.
static NVRTC: Mutex<()> = Mutex::new(());

/// Compile (or fetch from cache) the given self-contained CUDA source and return the kernel.
/// The loaded module is cached by source hash, so requesting several kernel names from the same
/// generated source compiles and loads only once.
pub fn compile_kernel(source: &str, kernel_name: &str) -> Result<JitKernel, String> {
    let key = source_hash(source);
    let dev = crate::runtime::context::get_device().unwrap_or(0);
    {
        let cache = KERNEL_CACHE.lock().unwrap();
        if let Some(map) = cache.as_ref() {
            if let Some(k) = map.get(&(dev, key, kernel_name.to_string())) {
                return Ok(*k);
            }
        }
    }

    let module = {
        let cached = {
            let cache = MODULE_CACHE.lock().unwrap();
            cache.as_ref().and_then(|m| m.get(&(dev, key)).copied())
        };
        match cached {
            Some(m) => m as CUmodule,
            None => {
                // Poison is ignored: the mutex guards no invariant a panicking compile could
                // break, and every caller sits inside a `OnceLock::get_or_init` that would retry
                // and re-panic forever on a poisoned lock instead of falling back to the interpreter.
                let _nvrtc = NVRTC.lock().unwrap_or_else(|e| e.into_inner());
                // Re-checked under the lock: whoever we queued behind may have built this module.
                let cached = {
                    let cache = MODULE_CACHE.lock().unwrap();
                    cache.as_ref().and_then(|m| m.get(&(dev, key)).copied())
                };
                match cached {
                    Some(m) => m as CUmodule,
                    None => {
                        let m = compile_module(source, kernel_name)?;
                        let mut cache = MODULE_CACHE.lock().unwrap();
                        cache
                            .get_or_insert_with(HashMap::new)
                            .insert((dev, key), m as usize);
                        m
                    }
                }
            }
        }
    };

    unsafe {
        let c_kname = CString::new(kernel_name).unwrap();
        let mut func: CUfunction = ptr::null_mut();
        let rc = cuModuleGetFunction(&mut func, module, c_kname.as_ptr());
        if rc != 0 {
            return Err(format!("cuModuleGetFunction({kernel_name}) failed: {rc}"));
        }
        let kernel = JitKernel { func };
        let mut cache = KERNEL_CACHE.lock().unwrap();
        cache
            .get_or_insert_with(HashMap::new)
            .insert((dev, key, kernel_name.to_string()), kernel);
        Ok(kernel)
    }
}

/// Disk-cache path for a compiled cubin. `MLE_JIT_CACHE_DIR` overrides the dir (default
/// `.mle_jit_cache`; empty or `off` disables). `key` is the hash of the FULL nvrtc option list +
/// source (computed once in `compile_module`), so a cubin built under one arch/flag set is never
/// reused for another. Pre-warming this cache offline lets production runs load ready cubins and
/// skip nvrtc entirely — the fix for the libnvrtc many-compiles deadlock (the runtime process
/// then does zero compiles).
fn jit_cache_file(key: u64) -> Option<PathBuf> {
    let dir = std::env::var("MLE_JIT_CACHE_DIR").unwrap_or_else(|_| ".mle_jit_cache".to_string());
    if dir.is_empty() || dir == "off" {
        return None;
    }
    Some(PathBuf::from(dir).join(format!("{key:016x}.cubin")))
}

fn load_cubin(cubin: &[u8]) -> Result<CUmodule, String> {
    let mut module: CUmodule = ptr::null_mut();
    let rc = unsafe { cuModuleLoadData(&mut module, cubin.as_ptr() as *const c_void) };
    if rc != 0 {
        return Err(format!("cuModuleLoadData failed: {rc}"));
    }
    Ok(module)
}

/// `MLE_JIT_OFAST=1` adds `--Ofast-compile=max`: tells the NVVM frontend to prioritize compile
/// time. Measured on the pathological z1 round-0 kernel (9377 rules, giant loop body): default
/// flags never finish (>60 min), with this it compiles in ~152s. Off by default; the flag requires
/// a CUDA toolkit that supports `--Ofast-compile` (verify against the toolkit in use before
/// enabling — nvrtc rejects unknown options).
fn ofast_flag() -> Option<String> {
    let v = std::env::var("MLE_JIT_OFAST").ok()?;
    (v.trim() == "1").then(|| "--Ofast-compile=max".to_string())
}

/// The two JIT kernel families. Owning each family's env-var names + gate defaults here lets the
/// three former string vocabularies — the gate tags (`"g1jit"`/`"z1jit"`), the CUDA symbol names
/// (`"z1_round0"`/`"jit_interactions"`), and the `MLE_JIT_MAXRREG_{G1,Z1}` vars — resolve through
/// one type, so a renamed kernel can't silently drop its per-family flags.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum JitKind {
    /// G1: interaction evaluation (GKR input / logup MLE rounds).
    G1,
    /// Z1: round-0 zerocheck constraint evaluation.
    Z1,
}

impl JitKind {
    /// Classify a CUDA kernel symbol name into its family (for per-family compile flags).
    pub(crate) fn from_kernel_name(name: &str) -> Option<Self> {
        match name {
            "z1_round0" | "z1_reduce" => Some(Self::Z1),
            "jit_interactions" => Some(Self::G1),
            _ => None,
        }
    }
    /// Short log label.
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::G1 => "g1jit",
            Self::Z1 => "z1jit",
        }
    }
    /// `G1_JIT_MAX_RULES` / `Z1_JIT_MAX_RULES`: per-family size-gate override.
    pub(crate) fn max_rules_env(self) -> &'static str {
        match self {
            Self::G1 => "G1_JIT_MAX_RULES",
            Self::Z1 => "Z1_JIT_MAX_RULES",
        }
    }
    /// Measured-safe default size gate: keeps every hot-path core AIR JIT-ed, gates only the
    /// optional-precompile giants. **Mirrored by `single_node_mle.sh`'s `{G1,Z1}_JIT_MAX_RULES`
    /// defaults — change both together.**
    ///
    /// An AIR over the gate keeps `jit_source = None` and runs the rule-interpreting kernel —
    /// correct, just slower — so the value carries headroom rather than sitting at the tightest
    /// admitting count: **any gate between the largest admitted AIR and the smallest gated-out one
    /// admits the same set**, and only the admitted side degrades without an error. Both of those
    /// rule counts move whenever an AIR changes, so they are not quoted here;
    /// `jit_rules_within_gate` warns when an AIR actually crosses.
    pub(crate) fn default_max_rules(self) -> usize {
        match self {
            Self::G1 => 2000,
            Self::Z1 => 11000,
        }
    }
    /// `MLE_JIT_MAXRREG_G1` / `MLE_JIT_MAXRREG_Z1`: per-family register cap.
    pub(crate) fn maxrreg_env(self) -> &'static str {
        match self {
            Self::G1 => "MLE_JIT_MAXRREG_G1",
            Self::Z1 => "MLE_JIT_MAXRREG_Z1",
        }
    }
}

/// Read a boolean knob. Unset returns `default`; `1`/`true`/`yes`/`on` and `0`/`false`/`no`/`off`
/// (trimmed, case-insensitive) set it; an empty value reads as off, since that is how a launcher
/// clears a variable. Anything else warns and returns `default`.
///
/// Two traps this closes, both of which have shipped here. `std::env::var(V).is_ok()` makes `V=0`
/// mean ON — the operator turns a knob off and gets it on. `is_ok_and(|v| v != "0")` fixes the
/// literal `"0"` and still lets `"0\n"` (a value read from a file or a command substitution),
/// `""` and `false` mean ON. A value that plainly reads as off must be off, and a value nobody
/// can classify must not silently pick a side.
pub(crate) fn env_flag(var: &str, default: bool) -> bool {
    let Ok(v) = std::env::var(var) else {
        return default;
    };
    match v.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => true,
        "0" | "false" | "no" | "off" | "" => false,
        _ => {
            tracing::warn!("[jit] unparseable {var}={v:?}; using default {default}");
            default
        }
    }
}

/// Parse a `usize` JIT knob env var, warning **loudly** (not silently falling back) on an
/// unparseable value: a typo'd knob otherwise silently reverts to default and can re-expose the
/// compile-infeasible giants the gates exist to prevent. Unset returns `default` quietly.
pub(crate) fn env_usize_or_warn(var: &str, default: usize) -> usize {
    match std::env::var(var) {
        Err(_) => default,
        Ok(v) => v.trim().parse().unwrap_or_else(|_| {
            tracing::warn!("[jit] unparseable {var}={v:?}; using default {default}");
            default
        }),
    }
}

/// Read a per-family env var, falling back to a generic one. `specific` is `None` when the family
/// is unknown (e.g. a kernel name outside the JIT set), in which case only the generic var applies.
pub(crate) fn per_type_or_generic_env(specific: Option<&str>, generic: &str) -> Option<String> {
    specific
        .and_then(|s| std::env::var(s).ok())
        .or_else(|| std::env::var(generic).ok())
}

/// MLE_JIT_MAXRREG=<n> adds --maxrregcount=<n>: caps registers per thread to lift the
/// occupancy ceiling on the big straight-line z1 kernels (measured: 255 regs -> 16.7%
/// theoretical occupancy, SM throughput 27%). Spills go to local memory — A/B test only.
fn maxrreg_flag(kernel_name: &str) -> Option<String> {
    let per_type = JitKind::from_kernel_name(kernel_name).map(|k| k.maxrreg_env());
    let v = per_type_or_generic_env(per_type, "MLE_JIT_MAXRREG")?;
    match v.trim().parse::<u32>() {
        Ok(n) => Some(format!("--maxrregcount={n}")),
        Err(_) => {
            tracing::warn!("[jit] unparseable MLE_JIT_MAXRREG(_G1/_Z1)={v:?}; ignoring");
            None
        }
    }
}

fn compile_module(source: &str, kernel_name: &str) -> Result<CUmodule, String> {
    let arch = device_arch_flag().map_err(|e| format!("device arch: {e:?}"))?;
    // The FULL nvrtc option list. Every option — including the static ones — is folded into the
    // cache key below, so any future change to the compile recipe automatically invalidates old
    // cubins instead of silently loading stale ones.
    let mut opts_str: Vec<String> = vec![
        arch,
        "-std=c++17".to_string(),
        "-default-device".to_string(),
    ];
    opts_str.extend(ofast_flag());
    opts_str.extend(maxrreg_flag(kernel_name));
    // Single cache key shared by the cubin cache and the source dump (their filenames must match
    // — the dump exists so a dumped `<key>.cu` can be compiled offline and seeded as `<key>.cubin`).
    let key = source_hash(&format!("{}\x00{source}", opts_str.join("\x01")));
    let cache_file = jit_cache_file(key);

    // Diagnostic: dump the generated source as `<key>.cu` (`MLE_JIT_DUMP_DIR`), cache hit or not.
    // Lets us capture a pathological kernel's source offline and probe nvrtc flags on it without
    // the full prover.
    if let Ok(dump_dir) = std::env::var("MLE_JIT_DUMP_DIR") {
        if !dump_dir.is_empty() {
            let _ = std::fs::create_dir_all(&dump_dir);
            let _ = std::fs::write(
                PathBuf::from(&dump_dir).join(format!("{key:016x}.cu")),
                source,
            );
        }
    }

    // Disk-cache hit: load the ready cubin and skip nvrtc entirely (this is what avoids the
    // many-compiles deadlock — a warm cache means zero nvrtc calls at runtime). A stale/incompatible
    // entry that fails to load falls through to a recompile.
    if let Some(f) = &cache_file {
        if let Ok(cubin) = std::fs::read(f) {
            if !cubin.is_empty() {
                if let Ok(module) = load_cubin(&cubin) {
                    return Ok(module);
                }
            }
        }
    }

    let c_src = CString::new(source).map_err(|e| e.to_string())?;
    let c_name = CString::new("jit_gen.cu").unwrap();
    let mut prog: nvrtcProgram = ptr::null_mut();
    let cubin: Vec<u8> = unsafe {
        let rc = nvrtcCreateProgram(
            &mut prog,
            c_src.as_ptr(),
            c_name.as_ptr(),
            0,
            ptr::null(),
            ptr::null(),
        );
        if rc != 0 {
            return Err(format!("nvrtcCreateProgram failed: {rc}"));
        }
        // Compile to CUBIN (real SM arch) + `-default-device`, mirroring the working FRI quotient
        // JIT recipe: ptxas runs inside nvrtc and yields a ready SASS image, so module load does NOT
        // invoke the CUDA driver's PTX→SASS JIT.
        let c_opts: Vec<CString> = opts_str
            .iter()
            .map(|o| CString::new(o.as_str()).unwrap())
            .collect();
        let opts: Vec<*const i8> = c_opts.iter().map(|c| c.as_ptr()).collect();
        let rc = nvrtcCompileProgram(prog, opts.len() as i32, opts.as_ptr());
        if rc != 0 {
            let mut log_size = 0usize;
            nvrtcGetProgramLogSize(prog, &mut log_size);
            let mut log = vec![0i8; log_size.max(1)];
            nvrtcGetProgramLog(prog, log.as_mut_ptr());
            let log_str =
                String::from_utf8_lossy(&log.iter().map(|&c| c as u8).collect::<Vec<_>>())
                    .into_owned();
            nvrtcDestroyProgram(&mut prog);
            return Err(format!("nvrtc compile failed ({rc}): {log_str}"));
        }
        let mut cubin_size = 0usize;
        let rc = nvrtcGetCUBINSize(prog, &mut cubin_size);
        if rc != 0 || cubin_size == 0 {
            nvrtcDestroyProgram(&mut prog);
            return Err(format!(
                "nvrtcGetCUBINSize failed: rc={rc} size={cubin_size}"
            ));
        }
        let mut cubin_i8 = vec![0i8; cubin_size];
        let rc = nvrtcGetCUBIN(prog, cubin_i8.as_mut_ptr());
        nvrtcDestroyProgram(&mut prog);
        if rc != 0 {
            return Err(format!("nvrtcGetCUBIN failed: rc={rc}"));
        }
        cubin_i8.iter().map(|&b| b as u8).collect()
    };

    // Load first, persist after (best-effort, atomic temp+rename): only a cubin the driver
    // actually accepted is worth caching — a bad artifact written first would be retried by
    // every future process before falling through to a recompile.
    let module = load_cubin(&cubin)?;
    if let Some(f) = &cache_file {
        if let Some(dir) = f.parent() {
            let _ = std::fs::create_dir_all(dir);
        }
        let tmp = f.with_extension(format!("tmp.{}", std::process::id()));
        if std::fs::write(&tmp, &cubin).is_ok() {
            let _ = std::fs::rename(&tmp, f);
        }
    }
    Ok(module)
}

impl JitKernel {
    /// Launch with raw kernel parameters on the default (per-thread) stream.
    ///
    /// # Safety
    /// `params` must match the generated kernel's signature exactly.
    pub unsafe fn launch(
        &self,
        grid: u32,
        block: u32,
        shared_bytes: u32,
        params: &mut [*mut c_void],
    ) -> Result<(), String> {
        let rc = cuLaunchKernel(
            self.func,
            grid,
            1,
            1,
            block,
            1,
            1,
            shared_bytes,
            // Named, not the legacy null stream: legacy work implicitly synchronizes with every
            // blocking stream in the context, which serializes one prover lane against the other
            // and fails the graph capture in `rs_ntt_fastpath.cu` with
            // `cudaErrorStreamCaptureImplicit`. Harmless with one lane per card; fatal with two.
            CU_STREAM_PER_THREAD,
            params.as_mut_ptr(),
            ptr::null_mut(),
        );
        if rc != 0 {
            return Err(format!("cuLaunchKernel failed: {rc}"));
        }
        Ok(())
    }
}
