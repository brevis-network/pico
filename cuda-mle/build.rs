// The `builder` module below is a general-purpose fluent API; not all of its methods are used
// here.
#![allow(dead_code)]

//! Build script for `cuda-mle`.
//!
//! Compiles the KoalaBear kernel libraries with the nvcc helper in the `builder` module below.
//! No allocator shim is built: device allocations go through an external `cudaMemPool_t` or
//! `cudaMallocAsync` (see `runtime::memory_manager`).

use std::process::exit;

use builder::{cuda_available, KernelLibBuilder};

fn main() {
    if !cuda_available() {
        eprintln!("cargo:warning=CUDA is not available");
        exit(1);
    }

    // The kernels live in pico-gpu and are compiled from there, whole: each .cu under its
    // src/prover/ directory carries its kernels and its `extern "C"` entry points.
    // `DEP_PICO_GPU_ROOT` comes from the `pico-gpu` crate's `links` key.
    //
    // The pico-gpu root is NOT an include path. The sources include each other by their path
    // from src/ (`field/fp.h`, `prover/reduce.cuh`, ...); the third_party/sppark roots sit
    // beside it. Where the order of the roots matters is noted in the `cuda_kb_all` builder.
    let pico_root = std::env::var("DEP_PICO_GPU_ROOT")
        .expect("DEP_PICO_GPU_ROOT not set: cuda-mle must depend on the `pico-gpu` crate");
    let sppark = format!("{pico_root}/third_party/sppark");
    let pico_src = format!("{pico_root}/src");
    let prover = format!("{pico_src}/prover");
    // The directory as well as its files: a .cu added there must re-run this script, and the
    // per-file watches `.file()` registers only cover files that already existed.
    println!("cargo:rerun-if-changed={sppark}");
    println!("cargo:rerun-if-changed={pico_src}");

    // ── mle-kernels: hashing and device info ─────────────────────────────────
    //
    // `sponge.cu` and `merkle_tree.cu` declare `using Fp = kb31_t;` themselves; `device_info.cu`
    // is field-free. Every file is named: `src/prover/` also holds the sources `cuda_kb_all`
    // compiles, and those need its include roots.
    let common = KernelLibBuilder::new().include(&sppark).include(&pico_src);

    common.emit_link_directives();
    // nvrtc + driver API for the runtime-generated interaction kernels (src/cuda/jit.rs).
    println!("cargo:rustc-link-lib=dylib=nvrtc");
    println!("cargo:rustc-link-lib=dylib=cuda");

    common
        .clone()
        .library_name("mle-kernels")
        .watch("cuda")
        .file("cuda/src/device_info.cu")
        .file(format!("{prover}/sponge.cu"))
        .file(format!("{prover}/merkle_tree.cu"))
        .build();

    // ── cuda_kb_all: the proving kernels, KoalaBear-typed ─────────────────────
    //
    // Combines NTT + proving kernels into ONE library so device symbols (DEVICE_NTT_TWIDDLES, …)
    // are defined in the same link unit that uses them. `CUDA_KB_RS_FASTPATH` turns on the
    // RS-encode fast path (src/prover/ntt/rs_ntt_fastpath.cu) inside the NTT sources.
    // Include order: sppark's KoalaBear NTT root MUST come before its generic NTT root, since
    // both provide `ntt/ntt.cuh` and the KoalaBear one is the wrapper the sources want.
    KernelLibBuilder::new()
        .library_name("cuda_kb_all")
        .include(format!("{sppark}/ntt_koalabear/include")) // KB NTT params + ntt.cuh wrapper
        .include(format!("{sppark}/ntt/include")) // ntt.cuh helpers
        .include(&sppark) // ff/mont32_t.cuh, ff/koala_bear_ext.hpp
        .include(&pico_src) // "common/...", "field/..." etc.
        .include(format!("{pico_src}/common")) // third_party/sppark's bare "launcher.cuh"
        .flag("-DCUDA_KB_RS_FASTPATH=1")
        .file(format!("{sppark}/ntt/ntt.cu"))
        .file(format!("{sppark}/ntt/ntt_params.cu"))
        .file(format!("{sppark}/ntt_koalabear/ntt_bitrev_kb.cu"))
        .file(format!("{prover}/ntt/rs_ntt_fastpath.cu"))
        .file(format!("{prover}/ntt/batch_ntt_small.cu"))
        .file(format!("{prover}/logup_zerocheck/logup_round0.cu"))
        .file(format!("{prover}/logup_zerocheck/zerocheck_round0.cu"))
        .file(format!("{prover}/logup_zerocheck/batch_mle.cu"))
        .file(format!("{prover}/logup_zerocheck/eval_mle.cu"))
        .file(format!("{prover}/logup_zerocheck/gkr.cu"))
        .file(format!("{prover}/logup_zerocheck/gkr_input.cu"))
        .file(format!("{prover}/logup_zerocheck/utils.cu"))
        .file(format!("{prover}/logup_zerocheck/batch_mle_monomial.cu"))
        .file(format!("{prover}/whir.cu"))
        .file(format!("{prover}/sumcheck.cu"))
        .file(format!("{prover}/poly.cu"))
        .file(format!("{prover}/matrix.cu"))
        .file(format!("{prover}/mle_interpolate.cu"))
        .file(format!("{prover}/stacked_reduction.cu"))
        .watch(&sppark)
        .watch(&pico_src)
        .build();
}

/// nvcc build helper: collects sources, include paths, flags and watches, compiles a static
/// library and emits the cargo link directives for it.
mod builder {
    use std::{env, path::Path, process::Command};

    /// Everything one nvcc static-library build needs, accumulated through the chained setters
    /// and consumed by [`KernelLibBuilder::build`].
    #[derive(Debug, Clone)]
    pub struct KernelLibBuilder {
        /// `-I` roots, passed to nvcc in insertion order (the order matters for header shadowing).
        include_dirs: Vec<String>,
        /// `.cu` translation units of the library, compiled in insertion order.
        cu_sources: Vec<String>,
        /// Paths reported to cargo with `rerun-if-changed`.
        rerun_paths: Vec<String>,
        /// Glob patterns expanded at build time into further `rerun-if-changed` lines.
        rerun_globs: Vec<String>,
        /// Name handed to `cc` for the produced static library.
        output_lib: String,
        /// Explicit SM targets; when empty the `CUDA_ARCH` env var or the local GPU decides.
        arch_override: Vec<String>,
        /// Explicit ptxas optimisation level; when unset `CUDA_OPT_LEVEL` (default 3) decides.
        opt_level_override: Option<String>,
        /// Forces `-lineinfo` on, in addition to the `CUDA_LINEINFO=1` switch.
        force_lineinfo: bool,
        /// Extra nvcc flags, emitted before the per-arch `-gencode` pairs.
        nvcc_flags: Vec<String>,
        /// Libraries announced with `rustc-link-lib`.
        linked_libs: Vec<String>,
        /// Directories announced with `rustc-link-search=native`.
        lib_search_dirs: Vec<String>,
    }

    impl Default for KernelLibBuilder {
        fn default() -> Self {
            // The CUDA runtime is looked up in `CUDA_LIB_DIR` when set, else in the stock
            // toolkit location.
            let mut runtime_dirs = Vec::new();
            if let Ok(lib_dir_from_env) = env::var("CUDA_LIB_DIR") {
                runtime_dirs.push(lib_dir_from_env);
            } else {
                runtime_dirs.push("/usr/local/cuda/lib64".to_string());
            }

            Self {
                include_dirs: Vec::new(),
                cu_sources: Vec::new(),
                rerun_paths: vec!["build.rs".to_string()],
                rerun_globs: Vec::new(),
                output_lib: String::new(),
                arch_override: Vec::new(),
                opt_level_override: None,
                force_lineinfo: false,
                nvcc_flags: vec![
                    "--std=c++17".to_string(),
                    "--expt-relaxed-constexpr".to_string(),
                    "-Xfatbin=-compress-all".to_string(),
                    "--default-stream=per-thread".to_string(),
                ],
                linked_libs: vec!["cudart".to_string(), "cuda".to_string()],
                lib_search_dirs: runtime_dirs,
            }
        }
    }

    impl KernelLibBuilder {
        pub fn new() -> Self {
            Self::default()
        }

        pub fn library_name(mut self, name: &str) -> Self {
            self.output_lib = name.to_string();
            self
        }

        /// Adds an include root (also watched for changes).
        pub fn include<P: AsRef<Path>>(mut self, path: P) -> Self {
            let dir = path.as_ref().to_string_lossy().to_string();
            self.include_dirs.push(dir.clone());
            self.rerun_paths.push(dir);
            self
        }

        /// Adds the include root named by a `DEP_*` variable, if the dependency exported one.
        pub fn include_from_dep(mut self, dep_env_var: &str) -> Self {
            if let Ok(exported_dir) = env::var(dep_env_var) {
                self.include_dirs.push(exported_dir);
            }
            self
        }

        /// Adds one source file (also watched for changes).
        pub fn file<P: AsRef<Path>>(mut self, path: P) -> Self {
            let source = path.as_ref().to_string_lossy().to_string();
            self.cu_sources.push(source.clone());
            self.rerun_paths.push(source);
            self
        }

        /// Adds several source files, in iteration order.
        pub fn files<P: AsRef<Path>, I: IntoIterator<Item = P>>(mut self, paths: I) -> Self {
            for entry in paths {
                let source = entry.as_ref().to_string_lossy().to_string();
                self.cu_sources.push(source.clone());
                self.rerun_paths.push(source);
            }
            self
        }

        /// Adds every `.cu` file the glob matches right now; files it matches at build time are
        /// also watched for changes.
        pub fn files_from_glob(mut self, pattern: &str) -> Self {
            self.rerun_globs.push(pattern.to_string());
            for matched in glob::glob(pattern).expect("Invalid glob pattern").flatten() {
                if matched.is_file() && matched.extension().is_some_and(|suffix| suffix == "cu") {
                    self.cu_sources.push(matched.to_string_lossy().to_string());
                }
            }
            self
        }

        pub fn watch<P: AsRef<Path>>(mut self, path: P) -> Self {
            self.rerun_paths
                .push(path.as_ref().to_string_lossy().to_string());
            self
        }

        pub fn watch_glob(mut self, pattern: &str) -> Self {
            self.rerun_globs.push(pattern.to_string());
            self
        }

        /// Pins a single SM target, overriding `CUDA_ARCH` and auto-detection.
        pub fn cuda_arch(mut self, arch: &str) -> Self {
            self.arch_override = vec![arch.to_string()];
            self
        }

        /// Pins a list of SM targets, overriding `CUDA_ARCH` and auto-detection.
        pub fn cuda_archs(mut self, archs: Vec<&str>) -> Self {
            self.arch_override = archs.iter().map(|sm| sm.to_string()).collect();
            self
        }

        pub fn cuda_opt_level(mut self, level: u8) -> Self {
            self.opt_level_override = Some(level.to_string());
            self
        }

        pub fn lineinfo(mut self, enabled: bool) -> Self {
            self.force_lineinfo = enabled;
            self
        }

        pub fn flag(mut self, flag: &str) -> Self {
            self.nvcc_flags.push(flag.to_string());
            self
        }

        pub fn link_lib(mut self, lib: &str) -> Self {
            self.linked_libs.push(lib.to_string());
            self
        }

        pub fn link_search<P: AsRef<Path>>(mut self, path: P) -> Self {
            self.lib_search_dirs
                .push(path.as_ref().to_string_lossy().to_string());
            self
        }

        /// Prints the `rustc-link-search` / `rustc-link-lib` lines for this configuration.
        pub fn emit_link_directives(&self) {
            for dir in &self.lib_search_dirs {
                println!("cargo:rustc-link-search=native={}", dir);
            }
            for linked in &self.linked_libs {
                println!("cargo:rustc-link-lib={}", linked);
            }
        }

        /// Compiles the configured sources into the static library `output_lib`.
        ///
        /// Arguments are added in a fixed sequence: `CUDA_DEBUG` flags, include roots,
        /// `$CUDA_PATH/include`, extra flags, one `-gencode` per target SM plus a PTX fallback
        /// for the newest one, the parallel-jobs flag, the optimisation flags, `-lineinfo`, and
        /// finally the sources.
        pub fn build(self) {
            self.check_inputs();
            self.print_rerun_directives();
            let target_archs = self.resolve_archs();

            let mut nvcc = cc::Build::new();
            nvcc.cuda(true);

            self.apply_cuda_debug_mode(&mut nvcc);

            let ptxas_level = self.resolve_opt_level();

            for dir in &self.include_dirs {
                nvcc.include(dir);
            }

            if let Ok(toolkit_root) = env::var("CUDA_PATH") {
                nvcc.include(format!("{}/include", toolkit_root));
            }

            for extra in &self.nvcc_flags {
                nvcc.flag(extra);
            }

            for sm in &target_archs {
                nvcc.flag("-gencode")
                    .flag(format!("arch=compute_{},code=sm_{}", sm, sm));
            }

            if let Some(newest_sm) = target_archs.iter().max() {
                nvcc.flag("-gencode").flag(format!(
                    "arch=compute_{},code=compute_{}",
                    newest_sm, newest_sm
                ));
            }

            nvcc.flag(nvcc_parallel_jobs());

            if ptxas_level == "0" {
                nvcc.debug(true).flag("-O0");
            } else {
                nvcc.debug(false)
                    .flag(format!("--ptxas-options=-O{}", ptxas_level));
            }

            if self.lineinfo_enabled() {
                nvcc.flag("-lineinfo");
            }

            for source in &self.cu_sources {
                nvcc.file(source);
            }

            nvcc.compile(&self.output_lib);
        }

        /// Panics on a configuration that cannot be built; only warns about paths that are
        /// missing on disk, leaving the hard error to nvcc.
        fn check_inputs(&self) {
            if self.output_lib.is_empty() {
                panic!("Library name must be set using .library_name(\"name\") before calling .build()");
            }
            if self.cu_sources.is_empty() {
                panic!("At least one source file must be added using .file() or .files() before calling .build()");
            }
            for source in &self.cu_sources {
                if !Path::new(source).exists() {
                    eprintln!("cargo:warning=CUDA source file does not exist: {}", source);
                }
            }
            for dir in &self.include_dirs {
                if !Path::new(dir).exists() {
                    eprintln!("cargo:warning=Include path does not exist: {}", dir);
                }
            }
        }

        /// Tells cargo which env vars and files should trigger a rebuild of the kernels.
        fn print_rerun_directives(&self) {
            println!("cargo:rerun-if-env-changed=CUDA_ARCH");
            println!("cargo:rerun-if-env-changed=CUDA_OPT_LEVEL");
            println!("cargo:rerun-if-env-changed=CUDA_DEBUG");
            println!("cargo:rerun-if-env-changed=CUDA_LINEINFO");
            println!("cargo:rerun-if-env-changed=NVCC_THREADS");
            for watched in &self.rerun_paths {
                println!("cargo:rerun-if-changed={}", watched);
            }
            for pattern in &self.rerun_globs {
                emit_glob_watches(pattern);
            }
        }

        /// Target SMs: the builder's own list, else the comma-separated `CUDA_ARCH`, else the
        /// GPU found by `nvidia-smi`.
        fn resolve_archs(&self) -> Vec<String> {
            if !self.arch_override.is_empty() {
                return self.arch_override.clone();
            }
            if let Ok(arch_list) = env::var("CUDA_ARCH") {
                return arch_list
                    .split(',')
                    .map(|entry| entry.trim().to_string())
                    .filter(|entry| !entry.is_empty())
                    .collect();
            }
            vec![detect_cuda_arch()]
        }

        /// ptxas level: the builder's own value, else `CUDA_OPT_LEVEL`, else "3".
        fn resolve_opt_level(&self) -> String {
            if let Some(pinned) = &self.opt_level_override {
                return pinned.clone();
            }
            env::var("CUDA_OPT_LEVEL").unwrap_or_else(|_| "3".to_string())
        }

        fn lineinfo_enabled(&self) -> bool {
            self.force_lineinfo
                || env::var("CUDA_LINEINFO")
                    .map(|value| value == "1")
                    .unwrap_or(false)
        }

        /// With `CUDA_DEBUG=1`: export the runtime debugging env vars and switch nvcc to device
        /// debug info, frame pointers and verbose ptxas, defining `CUDA_DEBUG` for the kernels.
        fn apply_cuda_debug_mode(&self, nvcc: &mut cc::Build) {
            if env::var("CUDA_DEBUG")
                .map(|value| value == "1")
                .unwrap_or(false)
            {
                env::set_var("CUDA_OPT_LEVEL", "0");
                env::set_var("CUDA_LAUNCH_BLOCKING", "1");
                env::set_var("RUST_BACKTRACE", "full");
                env::set_var("CUDA_ENABLE_COREDUMP_ON_EXCEPTION", "1");
                env::set_var("CUDA_DEVICE_WAITS_ON_EXCEPTION", "1");
                nvcc.flag("-G");
                nvcc.flag("-Xcompiler=-fno-omit-frame-pointer");
                nvcc.flag("-Xptxas=-v");
                nvcc.define("CUDA_DEBUG", "1");
            }
        }
    }

    /// True when an `nvcc` binary can be launched from `PATH`.
    pub fn cuda_available() -> bool {
        Command::new("nvcc").arg("--version").output().is_ok()
    }

    /// Asks `nvidia-smi` for the first GPU's compute capability and returns it without the dot
    /// ("8.9" -> "89"); the value is also exported as `CUDA_ARCH` to rustc and to this process.
    pub fn detect_cuda_arch() -> String {
        let smi_result = Command::new("nvidia-smi")
            .args(["--query-gpu=compute_cap", "--format=csv,noheader"])
            .output()
            .expect("Failed to run nvidia-smi - make sure NVIDIA drivers are installed");

        let smi_text =
            String::from_utf8(smi_result.stdout).expect("nvidia-smi output is not valid UTF-8");

        let compute_cap = smi_text
            .lines()
            .next()
            .expect("nvidia-smi failed to return compute capability")
            .trim()
            .replace('.', "");

        println!("cargo:rustc-env=CUDA_ARCH={}", compute_cap);
        env::set_var("CUDA_ARCH", &compute_cap);
        compute_cap
    }

    /// nvcc `-t<N>` flag: `NVCC_THREADS` when it parses, else the host's available parallelism
    /// (1 if unknown).
    pub fn nvcc_parallel_jobs() -> String {
        let host_parallelism = std::thread::available_parallelism()
            .map(|count| count.get())
            .unwrap_or(1);

        let job_count = env::var("NVCC_THREADS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(host_parallelism);

        format!("-t{}", job_count)
    }

    /// Emits a `rerun-if-changed` line for every regular file the glob currently matches.
    fn emit_glob_watches(pattern: &str) {
        for matched in glob::glob(pattern).expect("Invalid glob pattern").flatten() {
            if matched.is_file() {
                println!("cargo:rerun-if-changed={}", matched.display());
            }
        }
    }
}
