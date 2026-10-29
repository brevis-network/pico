use std::{
    collections::HashMap,
    env, fs,
    path::{Path, PathBuf},
    process::Command,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Mutex,
    },
    time::Instant,
};

use sha2::{Digest, Sha256};
use walkdir::WalkDir;

/// Upper bound on concurrent nvcc processes. Each peaks near 1GB of RSS, and extra
/// jobs buy nothing here: chips_group2.cu alone takes 106s of a 222s serial batch,
/// so it sets the floor and four workers already hide every other source behind it.
/// Measured 222s serial, 104s at four jobs, 102s at eight.
const MAX_NVCC_JOBS: usize = 4;

// =====================================================================
// STEP 1: CARGO RERUN CONFIGURATION
// =====================================================================

/// Configures when Cargo should rerun this build script
///
/// WORKFLOW STEP 1.1: Set up file watching for automatic rebuilds
/// - Monitors build.rs itself for changes
/// - Monitors only source files (.cpp, .cu) for changes
/// - Headers are tracked via dependency analysis, not file watching
/// - This reduces unnecessary build script reruns when headers change
fn configure_rerun_conditions(cuda_source_dir: &Path) {
    // STEP 1.1a: Always rerun when build script itself changes.
    // NB the key is `cargo:rerun-if-changed`; `cargo:rustc-rerun-if-changed` is not a cargo
    // directive and is silently ignored.
    println!("cargo:rerun-if-changed=build.rs");

    // STEP 1.1b: Only watch source files, not headers
    // (headers are tracked via dependency analysis in Step 4)
    WalkDir::new(cuda_source_dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| {
            // Monitor source files AND headers
            // We must monitor headers so that build.rs actually runs when they change.
            // Once build.rs runs, its internal dependency analysis will decide if recompilation is needed.
            e.path().extension().is_some_and(|ext| {
                ext == "cpp" || ext == "cu" || ext == "cuh" || ext == "h" || ext == "hpp"
            })
        })
        .for_each(|e| println!("cargo:rerun-if-changed={}", e.path().display()));
}

// =====================================================================
// STEP 2: SOURCE FILE COLLECTION
// =====================================================================

/// Efficiently collects all C++/CUDA source files from multiple directories
///
/// WORKFLOW STEP 2.1: Scan directories for compilable sources
/// This function consolidates source discovery from multiple directories
/// (main CUDA dir + pico-gpu dependencies) into a single operation
fn collect_all_sources(directories: &[&Path]) -> Vec<String> {
    let mut sources = Vec::new();

    // STEP 2.1a: Iterate through each provided directory
    for &dir in directories {
        if dir.exists() {
            // STEP 2.1b: Recursively walk directory tree
            WalkDir::new(dir)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| {
                    // STEP 2.1c: Only collect compilable source files
                    e.path()
                        .extension()
                        .is_some_and(|ext| ext == "cpp" || ext == "cu")
                })
                .for_each(|e| sources.push(e.path().display().to_string()));
        }
    }

    sources
}

// =====================================================================
// STEP 3: WORK SCHEDULING
// =====================================================================

/// Runs `task` over every item across a bounded worker pool, preserving input order.
///
/// Used for both the dependency scan and the compilations: nvcc is a separate
/// process either way, so the only thing needed is a way to keep a fixed number
/// of them in flight.
fn parallel_map<T, R, F>(items: &[T], jobs: usize, task: F) -> Vec<R>
where
    T: Sync,
    R: Send,
    F: Fn(&T) -> R + Sync,
{
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::with_capacity(items.len()));

    std::thread::scope(|scope| {
        for _ in 0..jobs.min(items.len().max(1)) {
            scope.spawn(|| loop {
                let index = next.fetch_add(1, Ordering::Relaxed);
                let Some(item) = items.get(index) else {
                    return;
                };
                let value = task(item);
                results.lock().unwrap().push((index, value));
            });
        }
    });

    let mut collected = results.into_inner().unwrap();
    collected.sort_by_key(|(index, _)| *index);
    collected.into_iter().map(|(_, value)| value).collect()
}

/// How many nvcc processes to keep in flight, following Cargo's own -j.
fn nvcc_jobs() -> usize {
    env::var("NUM_JOBS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .or_else(|| std::thread::available_parallelism().ok().map(|n| n.get()))
        .unwrap_or(4)
        .clamp(1, MAX_NVCC_JOBS)
}

// =====================================================================
// STEP 4: FINGERPRINTING
// =====================================================================

/// Asks nvcc which headers a source actually pulls in.
///
/// This replaces a hand-rolled `#include` scanner that could not see through
/// conditional compilation or include-path precedence. That was harmless while
/// every build recompiled everything, but once a fingerprint decides whether an
/// object may be reused, a missed header means silently linking stale device code.
/// `-MM` costs about 0.2s per source against 6s to 106s to compile one.
fn query_header_deps(source: &str, nvcc_base_args: &[String]) -> Vec<PathBuf> {
    let mut args = nvcc_base_args.to_vec();
    args.push("-MM".to_string());
    args.push(source.to_string());

    let output = Command::new("nvcc")
        .args(&args)
        .output()
        .expect("[CUDA Build] Failed to execute NVCC for the dependency scan");

    if !output.status.success() {
        panic!(
            "[CUDA Build] Dependency scan failed for {}:\n{}",
            source,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // `-MM` writes `foo.o: a.cuh b.cuh \` with backslash-newline continuations.
    let text = String::from_utf8_lossy(&output.stdout);
    let listed = text.split_once(':').map(|(_, rest)| rest).unwrap_or("");
    listed
        .split_whitespace()
        .filter(|token| *token != "\\")
        .map(PathBuf::from)
        .collect()
}

/// Fingerprints one source over everything that can change its object file: its
/// own bytes, the bytes of every header it includes, and the exact nvcc
/// invocation. The compiler identity is part of it because objects built by a
/// different toolchain, or for a different GPU architecture, are not
/// interchangeable — which is what makes a restored cache safe to trust.
fn fingerprint_source(
    source: &str,
    deps: &[PathBuf],
    nvcc_identity: &str,
    nvcc_base_args: &[String],
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(nvcc_identity.as_bytes());
    for arg in nvcc_base_args {
        hasher.update(arg.as_bytes());
        hasher.update([0u8]);
    }

    for path in std::iter::once(PathBuf::from(source)).chain(deps.iter().cloned()) {
        hasher.update(path.to_string_lossy().as_bytes());
        match fs::read(&path) {
            Ok(bytes) => hasher.update(&bytes),
            // An unreadable dependency counts as changed, so the source rebuilds
            // instead of quietly reusing an object we cannot justify.
            Err(_) => hasher.update(b"<unreadable>"),
        }
    }

    format!("{:x}", hasher.finalize())
}

/// Reads the `fingerprint<TAB>source` lines written by the previous build.
fn read_manifest(path: &Path) -> HashMap<String, String> {
    let Ok(text) = fs::read_to_string(path) else {
        return HashMap::new();
    };

    text.lines()
        .filter_map(|line| line.split_once('\t'))
        .map(|(fingerprint, source)| (source.to_string(), fingerprint.to_string()))
        .collect()
}

/// Writes the manifest only after every compilation succeeded, so a failed build
/// cannot leave behind fingerprints claiming objects are current.
fn write_manifest(path: &Path, entries: &[(&String, String)]) {
    let body: String = entries
        .iter()
        .map(|(source, fingerprint)| format!("{fingerprint}\t{source}\n"))
        .collect();

    fs::write(path, body).expect("[CUDA Build] Failed to write the object manifest");
}

// =====================================================================
// STEP 5: INCREMENTAL COMPILATION ENGINE
// =====================================================================

/// Decides which sources are out of date, then compiles those.
///
/// WORKFLOW STEP 5: staleness is decided by content fingerprint, not timestamps.
/// Timestamps cannot work here: `libgpu_api.so` is gitignored, so on any fresh
/// checkout it is absent, every header then reads as newer than it, and all
/// sources rebuild unconditionally. A fingerprint also survives being restored
/// from a cache, where every mtime is the restore time.
fn compile_sources_incrementally(
    sources: &[String],
    obj_dir: &Path,
    nvcc_base_args: &[String],
    nvcc_identity: &str,
) -> Vec<PathBuf> {
    println!("cargo:warning=[CUDA Build] === STEP 5: FINGERPRINTED COMPILATION ===");

    fs::create_dir_all(obj_dir).expect("[CUDA Build] Failed to create the object directory");
    let manifest_path = obj_dir.join("manifest.tsv");
    let jobs = nvcc_jobs();

    // STEP 5.1: Object paths follow `sources` order, so the link step gets a
    // deterministic list no matter what order compilations finish in.
    let object_files: Vec<PathBuf> = sources
        .iter()
        .map(|source| {
            let stem = PathBuf::from(source)
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned();
            obj_dir.join(format!("{stem}.o"))
        })
        .collect();

    // STEP 5.2: Fingerprint every source against the compiler's own dependency list
    println!("cargo:warning=[CUDA Build] STEP 5.2: Scanning dependencies...");
    let scan_started = Instant::now();
    let fingerprints = parallel_map(sources, jobs, |source| {
        let deps = query_header_deps(source, nvcc_base_args);
        fingerprint_source(source, &deps, nvcc_identity, nvcc_base_args)
    });
    println!(
        "cargo:warning=[CUDA Build] Fingerprinted {} sources in {:.1}s",
        sources.len(),
        scan_started.elapsed().as_secs_f64()
    );

    // STEP 5.3: A source is stale if its fingerprint moved or its object is gone.
    // The missing-object case matters for a partially restored cache.
    let recorded = read_manifest(&manifest_path);
    let pending: Vec<(&String, &PathBuf, &String)> = sources
        .iter()
        .zip(&object_files)
        .zip(&fingerprints)
        .filter(|((source, obj_path), fingerprint)| {
            recorded.get(*source) != Some(fingerprint) || !obj_path.exists()
        })
        .map(|((source, obj_path), fingerprint)| (source, obj_path, fingerprint))
        .collect();

    if pending.is_empty() {
        println!(
            "cargo:warning=[CUDA Build] All {} objects current",
            sources.len()
        );
        return object_files;
    }

    // STEP 5.4: Compile the stale sources across the worker pool
    println!("cargo:warning=[CUDA Build] STEP 5.4: Executing compilations...");
    let compile_started = Instant::now();

    let failures: Vec<(String, String)> = parallel_map(&pending, jobs, |(source, obj_path, _)| {
        let mut compile_args = nvcc_base_args.to_vec();
        compile_args.extend([
            "-c".to_string(),                        // Compile only, don't link
            "-o".to_string(),                        // Output file flag
            obj_path.to_string_lossy().into_owned(), // Object file output path
            (*source).clone(),                       // Source file input
        ]);

        let output = Command::new("nvcc")
            .args(&compile_args)
            .output()
            .expect("[CUDA Build] Failed to execute NVCC");

        // Reported rather than panicked: unwinding on a worker would discard the
        // diagnostics for every other source that failed in the same batch.
        (!output.status.success()).then(|| {
            (
                (*source).clone(),
                String::from_utf8_lossy(&output.stderr).into_owned(),
            )
        })
    })
    .into_iter()
    .flatten()
    .collect();

    if !failures.is_empty() {
        for (source, stderr) in &failures {
            eprintln!("NVCC Error in {source}:\n{stderr}");
        }
        panic!(
            "[CUDA Build] Compilation failed for {} of {} source(s)",
            failures.len(),
            pending.len()
        );
    }

    // STEP 5.5: Record fingerprints only now, so a failed build never leaves
    // behind a manifest claiming these objects are current.
    let entries: Vec<(&String, String)> = sources
        .iter()
        .zip(&fingerprints)
        .map(|(source, fingerprint)| (source, fingerprint.clone()))
        .collect();
    write_manifest(&manifest_path, &entries);

    // Reports the compile phase whenever this script actually runs. Note that Cargo
    // replays a cached script's output verbatim, so an identical line can appear for
    // an invocation that did nothing: to tell the two apart, compare step wall time
    // or the object mtimes rather than trusting this line alone.
    println!(
        "cargo:warning=[CUDA Build] Compiled {}/{} sources across {} job(s) in {:.1}s",
        pending.len(),
        sources.len(),
        jobs,
        compile_started.elapsed().as_secs_f64()
    );

    object_files
}

// =====================================================================

/// Links the object files into the shared library.
///
/// WORKFLOW STEP 6: always relinks. The previous timestamp check is not worth
/// keeping: linking measures 0.12s against a 104s compile, and the objects may
/// have come from a cache where every mtime is the restore time, so a timestamp
/// comparison could skip a link that was genuinely needed.
fn link_library(object_files: &[PathBuf], lib_path: &Path, nvcc_base_args: &[String]) {
    println!("cargo:warning=[CUDA Build] === STEP 6: LINKING ===");

    // STEP 6.2: Prepare linking arguments
    println!("cargo:warning=[CUDA Build] STEP 6.2: Preparing link arguments...");

    // STEP 6.2a: Filter out compilation-specific arguments
    let mut filtered_args = Vec::new();
    let mut i = 0;

    while i < nvcc_base_args.len() {
        let arg = &nvcc_base_args[i];
        if arg == "-gencode" {
            // STEP 6.2b: Skip -gencode and its parameter (not needed for linking)
            i += 2;
        } else if arg == "-c" {
            // STEP 6.2c: Skip -c flag (compilation only)
            i += 1;
        } else {
            // STEP 6.2d: Keep other arguments for linking
            filtered_args.push(arg.clone());
            i += 1;
        }
    }

    // STEP 6.2e: Add linking-specific arguments
    filtered_args.extend([
        "-shared".to_string(),                   // Create shared library
        "-o".to_string(),                        // Output file flag
        lib_path.to_string_lossy().into_owned(), // Library output path
        "-lnvrtc".to_string(),
        "-lcuda".to_string(),
    ]);

    // STEP 6.2f: Add all object files to be linked
    for obj in object_files {
        filtered_args.push(obj.to_string_lossy().into_owned());
    }

    println!(
        "cargo:warning=[CUDA Build] Link command: nvcc {}",
        filtered_args.join(" ")
    );

    // STEP 6.3: Execute linking
    println!("cargo:warning=[CUDA Build] STEP 6.3: Executing linker...");

    let output = Command::new("nvcc")
        .args(&filtered_args)
        .output()
        .expect("[CUDA Build] Failed to link");

    // STEP 6.4: Check linking result
    if !output.status.success() {
        println!(
            "cargo:warning=[CUDA Build] NVCC link stderr:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        panic!("[CUDA Build] Linking failed with status: {}", output.status);
    }

    println!("cargo:warning=[CUDA Build] Library linked successfully");
    println!("cargo:warning=[CUDA Build] === STEP 6 COMPLETE ===");
}

// =====================================================================
// MAIN BUILD ORCHESTRATION
// =====================================================================

/// Main build script orchestrator - coordinates the entire CUDA build process
///
/// WORKFLOW OVERVIEW:
/// 1. Environment Setup & Cargo Configuration
/// 2. Source Discovery & Dependency Management  
/// 3. Compiler Verification & Argument Preparation
/// 4. Incremental Compilation
/// 5. Incremental Linking
/// 6. Runtime Configuration
fn main() {
    println!("cargo:warning=[CUDA Build] ========================================");
    println!("cargo:warning=[CUDA Build] STARTING OPTIMIZED CUDA BUILD PROCESS");
    println!("cargo:warning=[CUDA Build] ========================================");

    // =====================================================================
    // WORKFLOW STEP 1: ENVIRONMENT SETUP & CARGO CONFIGURATION
    // =====================================================================
    println!("cargo:warning=[CUDA Build] === STEP 1: ENVIRONMENT SETUP ===");

    // STEP 1.1: Get build directories from Cargo environment
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let manifest_dir = PathBuf::from(env::var("CARGO_MANIFEST_DIR").unwrap());
    let cuda_dir = manifest_dir.parent().unwrap();
    let cuda_source_dir = manifest_dir.join("cuda");

    println!(
        "cargo:warning=[CUDA Build] Build output dir: {}",
        out_dir.display()
    );
    println!(
        "cargo:warning=[CUDA Build] CUDA source dir: {}",
        cuda_source_dir.display()
    );

    // STEP 1.2: Export information for dependent crates
    println!("cargo:ROOT={}", cuda_dir.to_string_lossy());

    // STEP 1.3: Configure Cargo linking directives
    println!("cargo:rustc-link-search=native={}", cuda_dir.display());
    println!("cargo:rustc-link-lib=dylib=gpu_api");

    // STEP 1.4: Set up intelligent file watching for rebuilds
    configure_rerun_conditions(&cuda_source_dir);

    // STEP 1.5: Define target library path
    let lib_path = cuda_dir.join("libgpu_api.so");
    fs::create_dir_all(cuda_dir).unwrap();

    println!(
        "cargo:warning=[CUDA Build] Target library: {}",
        lib_path.display()
    );

    // =====================================================================
    // WORKFLOW STEP 2: COMPILER VERIFICATION & NVCC SETUP
    // =====================================================================
    println!("cargo:warning=[CUDA Build] === STEP 2: COMPILER VERIFICATION ===");

    // STEP 2.1: Verify NVCC is available and capture its identity. The version
    // string goes into every object fingerprint, so objects built by one toolchain
    // are never reused by another.
    let nvcc_version = Command::new("nvcc")
        .arg("--version")
        .output()
        .expect("[CUDA Build] NVCC not found - please install CUDA toolkit");
    let nvcc_identity = String::from_utf8_lossy(&nvcc_version.stdout)
        .trim()
        .to_string();

    println!("cargo:warning=[CUDA Build] NVCC compiler verified");

    // STEP 2.2: Configure base NVCC compilation arguments
    let mut nvcc_base_args = vec![
        "-ccbin=/usr/bin/g++-11".to_string(), // Specify host compiler
        "-std=c++17".to_string(),             // C++17 standard
        "-Xcompiler".to_string(),
        "-fPIC".to_string(), // Position Independent Code for shared libs
        "-DFEATURE_KOALA_BEAR".to_string(), // Project-specific preprocessor definitions
        "-DKOALA_BEAR_CANONICAL".to_string(),
        "-DTAKE_RESPONSIBILITY_FOR_ERROR_MESSAGE".to_string(),
        "--extended-lambda".to_string(), // Enable CUDA extended lambda support
        "--ptxas-options=-v".to_string(), // Print register/shared memory usage per kernel
    ];

    // STEP 2.3: Handle GPU architecture targeting
    // `CUDA_ARCH` is the switch `cuda-mle` reads too.
    println!("cargo:rerun-if-env-changed=CUDA_ARCH");
    if let Ok(archs_str) = env::var("CUDA_ARCH") {
        println!(
            "cargo:warning=[CUDA Build] GPU target architectures: {}",
            archs_str
        );

        // Parse comma-separated architecture list for AOT compilation
        for arch in archs_str.split(',') {
            let arch_num = arch.trim();
            if !arch_num.is_empty() {
                nvcc_base_args.push("-gencode".to_string());
                nvcc_base_args.push(format!("arch=compute_{},code=sm_{}", arch_num, arch_num));
                println!("cargo:warning=[CUDA Build] Added target: sm_{}", arch_num);
            }
        }
    } else {
        println!("cargo:warning=[CUDA Build] No specific GPU targets, using JIT compilation");
    }

    // =====================================================================
    // WORKFLOW STEP 3: SOURCE DISCOVERY & DEPENDENCY MANAGEMENT
    // =====================================================================
    println!("cargo:warning=[CUDA Build] === STEP 3: SOURCE DISCOVERY ===");

    // STEP 3.1: Set up the directory list for source scanning. Header directories
    // are no longer collected: nvcc resolves includes from the -I flags, and it also
    // reports which headers each source actually pulled in.
    let mut source_dirs = vec![cuda_source_dir.as_path()];

    // STEP 3.2: Handle pico-gpu dependency integration
    let pico_gpu_root = env::var("DEP_PICO_GPU_ROOT").ok();
    let pico_gpu_path_buf = pico_gpu_root.as_ref().map(PathBuf::from);
    let pico_gpu_tracegen_dir = pico_gpu_path_buf.as_ref().map(|p| p.join("src/tracegen"));

    if let Some(ref pico_gpu_path) = pico_gpu_root {
        println!(
            "cargo:warning=[CUDA Build] Integrating pico-gpu dependency: {}",
            pico_gpu_path
        );

        // STEP 3.2a: Add pico-gpu's src/ as the include root ("tracegen/...", "common/...").
        nvcc_base_args.insert(0, format!("-I{}/src", pico_gpu_path));

        // CRITICAL FIX: Force Cargo to watch pico-gpu directory
        // Without this, changes to .cuh files in pico-gpu won't trigger this build script
        // because we only watch local .cu/.cpp files by default.
        // println!("cargo:rerun-if-changed={}", pico_gpu_path);

        // Explicitly monitor all header files in the pico-gpu directory
        if Path::new(pico_gpu_path).exists() {
            WalkDir::new(pico_gpu_path)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|e| {
                    e.path().extension().is_some_and(|ext| {
                        ext == "cuh" || ext == "h" || ext == "hpp" || ext == "cu" || ext == "cpp"
                    })
                })
                .for_each(|e| println!("cargo:rerun-if-changed={}", e.path().display()));
        }

        // STEP 3.2b: Add the pico-gpu source directories to the scan list
        if let Some(ref tracegen_dir) = pico_gpu_tracegen_dir {
            source_dirs.push(tracegen_dir.as_path());
        }
    }

    // STEP 3.3: Collect all source files from configured directories
    let final_sources = collect_all_sources(&source_dirs);

    println!(
        "cargo:warning=[CUDA Build] Found {} total source files",
        final_sources.len()
    );

    // =====================================================================
    // WORKFLOW STEP 4 & 5: FINGERPRINTED COMPILATION (implemented in function)
    // =====================================================================
    // Objects live beside the target directory rather than under OUT_DIR, because
    // OUT_DIR carries a per-profile and per-rustc-wrapper hash: Cargo and Clippy
    // get different ones, which previously meant compiling all 17 sources twice
    // per CI run. A single shared directory is also a fixed path CI can cache, and
    // being inside `target` it stays covered by Cargo's build-directory lock, so
    // concurrent invocations serialise instead of racing on the same objects.
    let obj_dir = out_dir
        .ancestors()
        .nth(4)
        .map(|target_dir| target_dir.join("cuda-objs"))
        .unwrap_or_else(|| out_dir.join("objects"));

    println!(
        "cargo:warning=[CUDA Build] Object directory: {}",
        obj_dir.display()
    );

    let object_files =
        compile_sources_incrementally(&final_sources, &obj_dir, &nvcc_base_args, &nvcc_identity);

    // =====================================================================
    // WORKFLOW STEP 6: LINKING (implemented in function)
    // =====================================================================
    link_library(&object_files, &lib_path, &nvcc_base_args);

    // =====================================================================
    // WORKFLOW STEP 7: RUNTIME CONFIGURATION
    // =====================================================================
    println!("cargo:warning=[CUDA Build] === STEP 7: RUNTIME CONFIGURATION ===");

    // STEP 7.1: Configure runtime library search path (rpath)
    // This ensures the executable can find the CUDA library at runtime
    println!("cargo:rustc-link-arg=-Wl,-rpath,{}", cuda_dir.display());
    println!(
        "cargo:warning=[CUDA Build] Added runtime library path: {}",
        cuda_dir.display()
    );

    // =====================================================================
    // FINAL STATUS REPORT
    // =====================================================================
    println!("cargo:warning=[CUDA Build] ========================================");
    println!("cargo:warning=[CUDA Build] BUILD COMPLETE");
    println!("cargo:warning=[CUDA Build] ========================================");
}
