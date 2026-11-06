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

#[cfg(feature = "pure-build")]
pub use build::{build_pure_library, PureBuildOptions};

#[cfg(feature = "pure-build")]
mod build {
    use std::{
        fs,
        path::{Path, PathBuf},
        process::Command,
    };

    use std::sync::atomic::{AtomicU64, Ordering};

    use pico_aot_codegen::{
        pure_dispatch_package, try_parse_elf, AotCompiler, AotConfig, RuntimeSpec,
        GENERATOR_FINGERPRINT,
    };
    use pico_aot_pure::{ABI_VERSION, SOURCE_FINGERPRINT};

    use super::elf_sha256;
    use crate::{error::hex, ProveError};

    /// Builds this process has started, so that two at once never share a scratch directory.
    static BUILDS: AtomicU64 = AtomicU64::new(0);

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
        /// The cargo to run; `cargo` on the `PATH` when `None`.
        pub cargo: Option<PathBuf>,
    }

    /// Generates `elf`'s pure-mode code and builds it into a dynamic library under `cache_dir`,
    /// keyed by the ELF's SHA-256, its decoded instructions, the pure ABI, the generator's and
    /// `pico-aot-pure`'s sources and the runtime entry; returns the library's path. A library
    /// already there is returned as it is. A failed build leaves nothing behind. Bytes that are not
    /// an ELF return [`ProveError::InvalidElf`], as `execute` does; a failed generation or cargo run
    /// returns [`ProveError::PureAotBuild`].
    ///
    /// Needs a Rust toolchain and cargo where it runs; a host that ships neither cannot build
    /// libraries, and `execute` then runs on the interpreter. Outside the Pico checkout
    /// `pico-prover` was compiled from, set [`PureBuildOptions::runtime`]. A build goes to a
    /// scratch directory and is moved into place when it is done, so two processes may build the
    /// same key.
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
        let key = format!(
            "{}-{decoded:016x}-abi{ABI_VERSION}-gen{GENERATOR_FINGERPRINT}-rt{SOURCE_FINGERPRINT:016x}-{:016x}",
            hex(&sha),
            fnv(runtime.as_bytes())
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

        let build = BUILDS.fetch_add(1, Ordering::Relaxed);
        let scratch = cache_dir.join(format!("{key}.build-{}-{build}", std::process::id()));
        if scratch.exists() {
            fs::remove_dir_all(&scratch)
                .map_err(|e| fail("cannot clear the build directory", &e))?;
        }
        let built = generate_and_build(program, &scratch, runtime, options);
        let installed = built.and_then(|built| {
            let dir = cache_dir.join(&key);
            fs::create_dir_all(&dir).map_err(|e| fail("cannot create the cache entry", &e))?;
            // Into the entry under a name of its own, then renamed: a reader sees all of it or
            // none.
            let staged = dir.join(format!("{file}.{}-{build}", std::process::id()));
            fs::copy(built.join(&file), &staged)
                .map_err(|e| fail("cannot copy the library", &e))?;
            fs::rename(&staged, &library).map_err(|e| fail("cannot install the library", &e))
        });
        let _ = fs::remove_dir_all(&scratch);
        installed.map(|()| library)
    }

    /// Generates `program`'s crates under `scratch` and builds them; returns where the library is.
    fn generate_and_build(
        program: pico_aot_codegen::ProgramInfo,
        scratch: &Path,
        runtime: String,
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
            .arg(scratch.join("target"));
        if options.offline {
            cargo.arg("--offline");
        }
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
        Ok(scratch.join("target/release"))
    }
}
