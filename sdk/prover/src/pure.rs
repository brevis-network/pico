//! Pure execution: [`crate::ProverBuilder::execute`] and [`crate::Prover::execute`].
//!
//! Runs the guest to its halt and reports what it committed and how many instructions it ran, and
//! nothing a proof needs: no chunks, records or snapshots. With a pure-mode AOT program for the
//! guest, linked in ([`crate::ProverBuilder::pure_aot`]) or loaded from a dynamic library
//! ([`PureLibrary`]), it runs the guest's compiled code; without one, a stepping interpreter, much
//! slower, with a warning. `require_pure_aot` refuses the interpreter instead.

use std::{
    path::Path,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
};

use pico_aot_pure::{PureProgram, ABI_VERSION, ENTRY_SYMBOL, SOURCE_FINGERPRINT};
use pico_aot_runtime::pure::{PureFailure, PureRun};
use pico_vm::{compiler::riscv::program::Program, mle::machine::riscv::EmulateError};
use sha2::{Digest, Sha256};

use crate::{ProveError, Stdin};

/// What ran a pure execution.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExecuteEngine {
    /// The guest's pure-mode AOT code.
    Aot,
    /// The stepping interpreter, for want of AOT code.
    Interpreter,
}

/// What a pure execution reports. The fields it shares with [`crate::Execution`] mean the same.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PureExecution {
    /// The bytes the guest committed, in commit order. Not authenticated: only a proof binds them.
    pub committed_bytes: Vec<u8>,
    /// Instructions the guest ran, as [`crate::Execution::cycles`] counts them.
    pub cycles: u64,
    /// Loads and stores whose address is not a multiple of their width, as
    /// [`crate::Execution::misaligned_accesses`] counts them.
    pub misaligned_accesses: u64,
    /// What ran it.
    pub engine: ExecuteEngine,
}

/// A pure-mode program loaded from a dynamic library, which stays loaded while this lives.
pub struct PureLibrary {
    program: *const PureProgram,
    // Dropped last: `program` points into it.
    _library: libloading::Library,
}

// SAFETY: `program` points at the library's static, immutable descriptor, valid while `_library`
// is loaded, and its `run` takes all its state through its argument.
unsafe impl Send for PureLibrary {}
unsafe impl Sync for PureLibrary {}

impl PureLibrary {
    /// Loads the library at `path`, built from a pure-mode dispatch crate with its `entry` feature,
    /// and checks it speaks this host's interface.
    ///
    /// # Safety
    ///
    /// Loading runs the library's initialisers. `path` must be a library generated and built by
    /// Pico's code generator, as [`build_pure_library`] makes one, from a trusted location.
    pub unsafe fn load(path: &Path) -> Result<Self, ProveError> {
        let load =
            |e: libloading::Error| ProveError::PureAotLoad(format!("`{}`: {e}", path.display()));
        // SAFETY: the caller vouches for the library.
        let library = unsafe { libloading::Library::new(path) }.map_err(load)?;
        // SAFETY: the symbol's type is `ENTRY_SYMBOL`'s, as the generator writes it.
        let program = unsafe {
            let entry: libloading::Symbol<unsafe extern "C" fn() -> *const PureProgram> =
                library.get(ENTRY_SYMBOL.as_bytes()).map_err(load)?;
            entry()
        };
        if program.is_null() {
            return Err(ProveError::PureAotLoad(format!(
                "`{}` returned no program",
                path.display()
            )));
        }
        // SAFETY: non-null, and static in the library.
        let (abi_version, fingerprint) =
            unsafe { ((*program).abi_version, (*program).source_fingerprint) };
        if abi_version != ABI_VERSION || fingerprint != SOURCE_FINGERPRINT {
            return Err(ProveError::PureAotLoad(format!(
                "`{}` was built against pico-aot-pure ABI {abi_version} ({fingerprint:016x}); this \
                 host has ABI {ABI_VERSION} ({SOURCE_FINGERPRINT:016x})",
                path.display()
            )));
        }
        Ok(Self {
            program,
            _library: library,
        })
    }

    /// The library's program.
    pub fn program(&self) -> &PureProgram {
        // SAFETY: checked non-null on load, and valid while the library is.
        unsafe { &*self.program }
    }
}

#[derive(Clone)]
enum Source {
    Static(&'static PureProgram),
    Library(Arc<PureLibrary>),
}

impl Source {
    fn program(&self) -> &PureProgram {
        match self {
            Self::Static(program) => program,
            Self::Library(library) => library.program(),
        }
    }
}

/// A builder's or a prover's pure-execution options.
#[derive(Clone, Default)]
pub(crate) struct PureOptions {
    source: Option<Source>,
    require_aot: bool,
    /// Why there is no AOT code, as the caller recorded it.
    unavailable: Option<Arc<str>>,
    /// Whether the interpreter warning has been logged, once per builder.
    warned: Arc<AtomicBool>,
}

impl PureOptions {
    pub(crate) fn set_static(&mut self, program: &'static PureProgram) {
        self.source = Some(Source::Static(program));
    }

    pub(crate) fn set_library(&mut self, library: Arc<PureLibrary>) {
        self.source = Some(Source::Library(library));
    }

    pub(crate) fn require_aot(&mut self, on: bool) {
        self.require_aot = on;
    }

    pub(crate) fn unavailable(&mut self, reason: String) {
        log::warn!("execute: no pure-mode AOT code ({reason}); it runs the stepping interpreter");
        self.warned.store(true, Ordering::Relaxed);
        self.unavailable = Some(reason.into());
    }

    /// Pure mode turned off on purpose: the interpreter runs, and nothing is logged about it. Drops
    /// any program set before; one set after turns it back on.
    pub(crate) fn disable(&mut self) {
        self.source = None;
        self.warned.store(true, Ordering::Relaxed);
        self.unavailable = Some("pure-mode execution is disabled".into());
    }

    pub(crate) fn fallback_reason(&self) -> Option<&str> {
        match self.source {
            Some(_) => None,
            None => self.unavailable.as_deref(),
        }
    }

    pub(crate) fn engine(&self) -> ExecuteEngine {
        match self.source {
            Some(_) => ExecuteEngine::Aot,
            None => ExecuteEngine::Interpreter,
        }
    }

    /// Runs `program`, compiled from the ELF whose SHA-256 is `elf_sha256`, on `stdin`, up to
    /// `max_cycles` instructions.
    pub(crate) fn execute(
        &self,
        program: Arc<Program>,
        elf_sha256: [u8; 32],
        stdin: Stdin,
        max_cycles: Option<u64>,
    ) -> Result<PureExecution, ProveError> {
        let aot = match &self.source {
            Some(source) => {
                let aot = source.program();
                if aot.elf_sha256 != elf_sha256 {
                    return Err(ProveError::PureAotElfMismatch {
                        generated_from: aot.elf_sha256,
                        elf: elf_sha256,
                    });
                }
                Some(aot)
            }
            None if self.require_aot => return Err(ProveError::PureAotRequired),
            None => {
                if !self.warned.swap(true, Ordering::Relaxed) {
                    log::warn!(
                        "execute: no pure-mode AOT program for this guest; running the stepping \
                         interpreter, which is much slower"
                    );
                }
                None
            }
        };
        let input_stream = stdin.into_emulator_stdin().inputs.to_vec();
        let mut run = PureRun::new(program, input_stream, max_cycles.unwrap_or(u64::MAX));
        let (engine, result) = match aot {
            Some(aot) => (ExecuteEngine::Aot, run.run_compiled(aot)),
            None => (ExecuteEngine::Interpreter, run.run_interpreted()),
        };
        result.map_err(from_failure)?;
        Ok(PureExecution {
            committed_bytes: run.committed_bytes().to_vec(),
            cycles: run.cycles(),
            misaligned_accesses: run.misaligned_accesses(),
            engine,
        })
    }
}

/// A pure run's failure, as the chunked emulation reports the same failure.
fn from_failure(failure: PureFailure) -> ProveError {
    match failure.error {
        Some(error) => ProveError::from_emulate(EmulateError::Emulation(error)),
        None => ProveError::EmulationAborted(failure.message),
    }
}

/// The SHA-256 of `elf`, as a pure-mode program records the ELF it was generated from.
pub(crate) fn elf_sha256(elf: &[u8]) -> [u8; 32] {
    Sha256::digest(elf).into()
}

#[cfg(all(test, feature = "pure-build"))]
pub(crate) use build::CARGO_RUNS;
#[cfg(feature = "pure-build")]
pub use build::{build_pure_library, PureBuildOptions};

#[cfg(feature = "pure-build")]
mod build {
    use std::{
        collections::hash_map::RandomState,
        fs,
        hash::{BuildHasher, Hasher},
        path::{Path, PathBuf},
        process::Command,
        sync::{
            atomic::{AtomicU64, Ordering},
            Mutex, OnceLock,
        },
        time::{SystemTime, UNIX_EPOCH},
    };

    use pico_aot_codegen::{
        pure_dispatch_package, try_parse_elf, AotCompiler, AotConfig, RuntimeSpec,
        GENERATOR_FINGERPRINT,
    };
    use pico_aot_pure::{ABI_VERSION, SOURCE_FINGERPRINT};

    use super::elf_sha256;
    use crate::{error::hex, ProveError};

    /// Draws for scratch names, so two in one process differ even within a clock tick.
    static DRAWS: AtomicU64 = AtomicU64::new(0);

    /// The scratch directory of every cargo run this process started; tests count builds with it.
    #[cfg(test)]
    pub(crate) static CARGO_RUNS: std::sync::Mutex<Vec<PathBuf>> =
        std::sync::Mutex::new(Vec::new());

    /// Variables, by name or by prefix, that would change what cargo builds behind the cache key's
    /// back: the build runs without them.
    const CLEARED_ENV: [&str; 2] = ["RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"];
    const CLEARED_ENV_PREFIXES: [&str; 3] = ["CARGO_BUILD_", "CARGO_PROFILE_", "CARGO_TARGET_"];

    /// A name no other build picks, in this process or another: containers all run as pid 1.
    fn unique_suffix() -> String {
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u64(DRAWS.fetch_add(1, Ordering::Relaxed));
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        format!("{}-{nanos:x}-{:016x}", std::process::id(), hasher.finish())
    }

    /// 64-bit FNV-1a offset basis: the hash's starting value.
    const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
    /// 64-bit FNV-1a prime: each byte is XORed in, then the hash is multiplied by it.
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    /// FNV-1a, for the cache key's decoded program and runtime entry.
    fn fnv(bytes: &[u8]) -> u64 {
        bytes.iter().fold(FNV_OFFSET_BASIS, |hash, &byte| {
            (hash ^ u64::from(byte)).wrapping_mul(FNV_PRIME)
        })
    }

    /// How [`build_pure_library`] builds.
    #[derive(Clone, Debug, Default)]
    pub struct PureBuildOptions {
        /// The `pico-aot-pure` the generated crates depend on, as the body of a Cargo dependency
        /// entry, e.g. `git = "https://github.com/brevis-network/pico", rev = "..."` or an
        /// absolute `path = "..."`. `None` takes this build's own source, by a path fixed when
        /// `pico-prover` was compiled, so it only works on a machine that has that checkout. A
        /// host elsewhere, such as a container image, names the same `pico-aot-pure` version
        /// here: a `rev` of the Pico commit it was built from, or a path into a full Pico checkout
        /// of that commit. `aot-pure/` takes its package fields from Pico's workspace, so a copy
        /// of that directory alone does not build.
        pub runtime: Option<String>,
        /// Pass `--offline` to cargo: every dependency must already be in its cache. For a host
        /// without network access, fetch `runtime` once when the host is set up (for a `git`
        /// entry, `cargo fetch` on any manifest that names it) and build offline after.
        pub offline: bool,
        /// The cargo to run; `cargo` on the `PATH` when `None`. Pico's lockfile is version 4, which
        /// takes cargo 1.78 or later.
        pub cargo: Option<PathBuf>,
    }

    /// Generates `elf`'s pure-mode code and builds it into a dynamic library under `cache_dir`,
    /// keyed by the ELF's SHA-256, its decoded instructions, the pure ABI, the generator's and
    /// `pico-aot-pure`'s sources, the runtime entry, Pico's lockfile and the toolchain (`rustc
    /// -vV`); returns the library's path. A library
    /// already there is returned as it is. A failed build leaves nothing behind. Bytes that are not
    /// an ELF return [`ProveError::InvalidElf`], as `execute` does; a failed generation or cargo run
    /// returns [`ProveError::PureAotBuild`].
    ///
    /// Needs a Rust toolchain and cargo where it runs, even to find a library already cached: the
    /// key holds the toolchain, so a host without `rustc` gets [`ProveError::PureAotBuild`] and
    /// `execute` runs on the interpreter. Outside the Pico checkout `pico-prover` was compiled
    /// from, set [`PureBuildOptions::runtime`]. Processes and containers may share `cache_dir`:
    /// one builds a key under a file lock while the others wait, and the library is moved into
    /// place only once complete; on a filesystem without file locks the build runs unlocked. The
    /// build is for the host, without any `RUSTFLAGS`, `CARGO_BUILD_*`, `CARGO_PROFILE_*` or
    /// `CARGO_TARGET_*` setting and without the caller's cargo config `rustflags`.
    pub fn build_pure_library(
        elf: &[u8],
        cache_dir: &Path,
        options: &PureBuildOptions,
    ) -> Result<PathBuf, ProveError> {
        let fail = |what: &str, e: &dyn std::fmt::Display| {
            ProveError::PureAotBuild(format!("{what}: {e}"))
        };
        let sha = elf_sha256(elf);
        // The decoded program too: the generator reads the VM's decoding, which may change apart
        // from the generator.
        let program = try_parse_elf(elf).map_err(ProveError::InvalidElf)?;
        let decoded = fnv(format!(
            "{:?}{}{}",
            program.instructions, program.pc_base, program.pc_start
        )
        .as_bytes());
        let runtime = match &options.runtime {
            Some(entry) => entry.clone(),
            None => format!(
                "path = {:?}",
                Path::new(env!("CARGO_MANIFEST_DIR")).join("../../aot-pure")
            ),
        };
        let toolchain = toolchain_id(options).map_err(|e| fail("cannot query rustc", &e))?;
        let key = format!(
            "{}-{decoded:016x}-abi{ABI_VERSION}-gen{GENERATOR_FINGERPRINT}-rt{SOURCE_FINGERPRINT:016x}-{:016x}-lock{:016x}-tc{:016x}",
            hex(&sha),
            fnv(runtime.as_bytes()),
            fnv(PICO_LOCKFILE.as_bytes()),
            fnv(toolchain.as_bytes())
        );
        let file = format!(
            "{}{}{}",
            std::env::consts::DLL_PREFIX,
            pure_dispatch_package(&sha).replace('-', "_"),
            std::env::consts::DLL_SUFFIX
        );
        let library = cache_dir.join(&key).join(&file);
        if library.is_file() {
            return Ok(library);
        }

        // One builder per key, across processes and containers sharing the cache: the others
        // wait here and then find the library.
        fs::create_dir_all(cache_dir).map_err(|e| fail("cannot create the cache", &e))?;
        let lock = open_lock(&cache_dir.join(format!("{key}.lock")))
            .map_err(|e| fail("cannot open the build lock", &e))?;
        match lock.lock() {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::Unsupported => log::warn!(
                "build_pure_library: {} has no file locks; building {key} unlocked",
                cache_dir.display()
            ),
            Err(e) => return Err(fail("cannot take the build lock", &e)),
        }
        if library.is_file() {
            return Ok(library);
        }
        clear_stale_scratch(cache_dir, &key);

        let suffix = unique_suffix();
        let scratch = cache_dir.join(format!("{key}.build-{suffix}"));
        let host = toolchain
            .lines()
            .find_map(|line| line.strip_prefix("host: "))
            .ok_or_else(|| fail("cannot read the host triple", &"`rustc -vV` names none"))?;
        let built = generate_and_build(program, &scratch, runtime, host, options);
        let installed = built.and_then(|built| {
            let dir = cache_dir.join(&key);
            fs::create_dir_all(&dir).map_err(|e| fail("cannot create the cache entry", &e))?;
            // Written in full and synced under a name of its own, then renamed: a reader sees all
            // of it or none, even after a crash.
            let staged = dir.join(format!("{file}.{suffix}"));
            fs::copy(built.join(&file), &staged)
                .and_then(|_| fs::File::open(&staged)?.sync_all())
                .and_then(|()| fs::rename(&staged, &library))
                .map_err(|e| {
                    let _ = fs::remove_file(&staged);
                    fail("cannot install the library", &e)
                })?;
            let _ = fs::File::open(&dir).and_then(|d| d.sync_all());
            Ok(())
        });
        let _ = fs::remove_dir_all(&scratch);
        installed.map(|()| library)
    }

    /// The toolchain cargo builds with (`rustc -vV`: version, commit and host triple), so a cache
    /// shared by hosts of other toolchains or architectures never hands one a library it cannot
    /// load.
    /// Asked once per `rustc` a process uses, not on every lookup.
    fn toolchain_id(options: &PureBuildOptions) -> std::io::Result<String> {
        static SEEN: OnceLock<Mutex<Vec<(PathBuf, String)>>> = OnceLock::new();
        let rustc = match &options.cargo {
            Some(cargo) => cargo.with_file_name("rustc"),
            None => PathBuf::from(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into())),
        };
        let seen = SEEN.get_or_init(Mutex::default);
        if let Some((_, id)) = seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .iter()
            .find(|(path, _)| *path == rustc)
        {
            return Ok(id.clone());
        }
        let output = Command::new(&rustc).arg("-vV").output()?;
        if !output.status.success() {
            return Err(std::io::Error::other(format!(
                "rustc -vV: {}",
                output.status
            )));
        }
        let id = String::from_utf8_lossy(&output.stdout).into_owned();
        seen.lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((rustc, id.clone()));
        Ok(id)
    }

    /// The key's lock file, created if missing; read-only where the cache is not writable by this
    /// user, which `flock` still accepts.
    fn open_lock(path: &Path) -> std::io::Result<fs::File> {
        match fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(path)
        {
            Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => fs::File::open(path),
            opened => opened,
        }
    }

    /// Removes scratch directories dead builds left: this key's, which nobody else can be using
    /// while its lock is held, and another key's once its lock is free, so its builder is gone. A
    /// directory with no lock file beside it is left alone: nothing shows its builder is dead.
    fn clear_stale_scratch(cache_dir: &Path, key: &str) {
        let Ok(entries) = fs::read_dir(cache_dir) else {
            return;
        };
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some((owner, _)) = name.to_str().and_then(|n| n.split_once(".build-")) else {
                continue;
            };
            let dead = owner == key
                || fs::File::open(cache_dir.join(format!("{owner}.lock")))
                    .is_ok_and(|lock| lock.try_lock().is_ok());
            if dead {
                let _ = fs::remove_dir_all(entry.path());
            }
        }
    }

    /// The workspace lockfile of the Pico checkout `pico-prover` was compiled from. Read from
    /// outside the crate, so `pico-prover` builds from a checkout, not from a packaged crate.
    const PICO_LOCKFILE: &str =
        include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../../Cargo.lock"));

    /// Generates `program`'s crates under `scratch` and builds them; returns where the library is.
    fn generate_and_build(
        program: pico_aot_codegen::ProgramInfo,
        scratch: &Path,
        runtime: String,
        host: &str,
        options: &PureBuildOptions,
    ) -> Result<PathBuf, ProveError> {
        let fail = |what: &str, e: &dyn std::fmt::Display| {
            ProveError::PureAotBuild(format!("{what}: {e}"))
        };
        let crates = scratch.join("crates");
        // The generator panics on an instruction it cannot translate; report that as a failed
        // build, so the caller still clears the scratch directory.
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            AotCompiler::new(program, AotConfig::new(crates.clone()).with_pure(true))
                .compile_with(&RuntimeSpec::Entry(runtime))
        }))
        .map_err(|panic| {
            let message = panic
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| panic.downcast_ref::<&str>().copied())
                .unwrap_or("no message");
            fail("the code generator panicked", &message)
        })?
        .map_err(|e| fail("cannot generate the pure-mode crates", &e))?;
        // Its own workspace, so it builds wherever the cache is, inside another workspace or not.
        // Only here: crates generated into a workspace for static linking join that one.
        let manifest = crates.join("Cargo.toml");
        fs::OpenOptions::new()
            .append(true)
            .open(&manifest)
            .and_then(|mut file| std::io::Write::write_all(&mut file, b"\n[workspace]\n"))
            .map_err(|e| fail("cannot write the dispatch manifest", &e))?;
        // Pico's own lockfile: the crates build against the dependency versions Pico was tested
        // with, not whatever the registry has today. Cargo drops the entries they do not use.
        fs::write(crates.join("Cargo.lock"), PICO_LOCKFILE)
            .map_err(|e| fail("cannot write the lockfile", &e))?;

        let mut cargo = Command::new(options.cargo.as_deref().unwrap_or(Path::new("cargo")));
        cargo
            .args([
                "rustc",
                "--release",
                "--features",
                "entry",
                "--crate-type",
                "cdylib",
            ])
            .arg("--manifest-path")
            .arg(&manifest)
            .arg("--target-dir")
            .arg(scratch.join("target"))
            // For the host whatever a cargo config says, and with no rustflags from one; run from
            // the scratch directory, so the caller's project config is not read.
            .args(["--target", host])
            .args(["--config", "build.rustflags=[]"])
            .args(["--config", &format!("target.{host}.rustflags=[]")])
            .current_dir(scratch);
        if options.offline {
            cargo.arg("--offline");
        }
        for var in CLEARED_ENV {
            cargo.env_remove(var);
        }
        for (var, _) in std::env::vars_os() {
            if var
                .to_str()
                .is_some_and(|v| CLEARED_ENV_PREFIXES.iter().any(|p| v.starts_with(p)))
            {
                cargo.env_remove(var);
            }
        }
        // Set and empty, it wins over every other source of rustflags, `cfg(...)` targets too.
        cargo.env("CARGO_ENCODED_RUSTFLAGS", "");
        #[cfg(test)]
        CARGO_RUNS.lock().unwrap().push(scratch.to_path_buf());
        let output = cargo.output().map_err(|e| fail("cannot run cargo", &e))?;
        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            let tail: Vec<&str> = stderr.lines().rev().take(20).collect();
            return Err(ProveError::PureAotBuild(format!(
                "cargo failed ({}):\n{}",
                output.status,
                tail.into_iter().rev().collect::<Vec<_>>().join("\n")
            )));
        }
        Ok(scratch.join("target").join(host).join("release"))
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        fn scratch(name: &str) -> PathBuf {
            let dir =
                std::env::temp_dir().join(format!("pico-pure-cache-{name}-{}", unique_suffix()));
            fs::create_dir_all(&dir).unwrap();
            dir
        }

        #[test]
        fn scratch_names_differ_within_one_process() {
            assert_ne!(unique_suffix(), unique_suffix());
        }

        /// Under its key's lock a build clears that key's leftovers, and another key's only once
        /// that key's lock is free; one with no lock file stays.
        #[test]
        fn a_dead_builds_scratch_is_cleared() {
            let cache = scratch("stale");
            let ours = cache.join("k1.build-1-a-b");
            let live = cache.join("k2.build-1-a-b");
            let dead = cache.join("k3.build-1-a-b");
            let unknown = cache.join("k4.build-1-a-b");
            let entry = cache.join("k3");
            for dir in [&ours, &live, &dead, &unknown, &entry] {
                fs::create_dir_all(dir).unwrap();
            }
            let held = open_lock(&cache.join("k2.lock")).unwrap();
            held.lock().unwrap();
            open_lock(&cache.join("k3.lock")).unwrap();

            clear_stale_scratch(&cache, "k1");

            assert!(!ours.exists() && !dead.exists());
            assert!(live.exists() && unknown.exists() && entry.exists());
            drop(held);
            fs::remove_dir_all(&cache).unwrap();
        }
    }
}
