use std::{
    fs, io,
    path::{Path, PathBuf},
};

use anyhow::{anyhow, bail, Context, Result};
use clap::Parser;
use pico_aot_codegen::{parse_elf, AotCompiler, AotConfig, RuntimeSpec};
use pico_vm::compiler::riscv::compiler::{Compiler, SourceType};

use crate::source::{check_release, pico_dependency, pico_source};

const DISPATCH_PACKAGE: &str = "pico-aot-dispatch";

#[derive(Parser)]
#[command(
    name = "aot",
    about = "Generate an ELF's AOT crates: a dispatch crate exporting `AOT`, and its chunk crates",
    after_help = "They take pico-aot-runtime from this CLI's release tag, or from the Pico checkout \
                  at PICO_SOURCE when it is set."
)]
pub struct AotCmd {
    /// ELF file path
    #[clap(long)]
    elf: PathBuf,

    /// The dispatch crate's directory, with the chunk crates under `chunks/`: new, empty, or a
    /// previous generation, which is replaced
    #[clap(long, value_name = "DIR")]
    out: PathBuf,
}

impl AotCmd {
    pub fn run(&self) -> Result<()> {
        let elf =
            fs::read(&self.elf).with_context(|| format!("cannot read `{}`", self.elf.display()))?;
        validate_elf(&self.elf, &elf)?;
        let pico_source = pico_source()?;
        if pico_source.is_none() {
            check_release()?;
        }
        let runtime = pico_dependency(pico_source.as_deref(), "aot-runtime");
        prepare_out(&self.out)?;
        let chunks = generate(&elf, &self.out, &runtime)?;
        println!(
            "generated: {DISPATCH_PACKAGE} and {chunks} chunk crate(s) in {}",
            self.out.display()
        );
        println!("runtime: pico-aot-runtime = {{ {runtime} }}");
        Ok(())
    }
}

/// What [`generate`] needs of `elf`, whose own parser panics on an ELF this rejects.
pub(crate) fn validate_elf(path: &Path, elf: &[u8]) -> Result<()> {
    Compiler::new(SourceType::RISCV, elf)
        .map_err(|e| anyhow!("`{}` is not a guest ELF: {e}", path.display()))?;
    Ok(())
}

/// Writes the crates for a [`validate_elf`]ed `elf` into `out`, depending on the runtime through
/// the dependency fields `runtime`, and returns how many chunk crates there are. `out` is deleted
/// first.
pub(crate) fn generate(elf: &[u8], out: &Path, runtime: &str) -> Result<usize> {
    AotCompiler::new(parse_elf(elf), AotConfig::new(out.to_path_buf()))
        .compile_with(&RuntimeSpec::Entry(runtime.to_owned()))
        .map_err(anyhow::Error::msg)
        .with_context(|| format!("cannot generate AOT crates in `{}`", out.display()))?;
    let chunks = out.join("chunks");
    Ok(fs::read_dir(&chunks)
        .with_context(|| format!("cannot list `{}`", chunks.display()))?
        .count())
}

/// The generator deletes its output directory before writing, so it is only ever handed one that
/// is empty or holds a previous generation.
fn prepare_out(out: &Path) -> Result<()> {
    let context = || format!("cannot write AOT crates to `{}`", out.display());
    match fs::read_dir(out) {
        Ok(mut entries) => {
            if entries.next().is_some() && !holds_dispatch_crate(out) {
                bail!(
                    "`{}` is not empty and holds no generated AOT crates; not replacing it",
                    out.display()
                );
            }
        }
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(context),
    }
    // Here rather than after generation, which takes a while.
    fs::create_dir_all(out).with_context(context)
}

fn holds_dispatch_crate(dir: &Path) -> bool {
    let name = format!("name = \"{DISPATCH_PACKAGE}\"");
    fs::read_to_string(dir.join("Cargo.toml"))
        .is_ok_and(|manifest| manifest.lines().any(|line| line == name))
}
