//! The prover's options, from flags and the environment.
//!
//! The prover library reads none of its options from the environment, so this is where the CLI
//! does. Every variable read here is echoed on stderr with the setter it became, so a run that
//! behaved unexpectedly says why. Whitelist mode needs `VK_VERIFICATION=true`, `MLE_VK_MAP` and
//! `MLE_VK_ROOT` together, at the default stacked height; a missing one is the prover's error to
//! report when it proves, and no default is filled in for it. The two whitelist variables are read
//! only under `VK_VERIFICATION=true`, and `execute` reads `CHUNK_SIZE` alone: a value nothing would
//! use must not stop the run.

use std::{fmt::Debug, num::NonZeroUsize, path::PathBuf};

use anyhow::{anyhow, Result};
use clap::Parser;
#[cfg(feature = "aot")]
use pico_aot_runtime::AotProgram;
use pico_prover::{Prover, ProverBuilder, ENV_NO_LONGER_READ, ENV_READ_BY_PROVER};

/// Every variable [`ProverArgs::resolve`] maps onto a builder option.
pub const MAPPED_ENV: &[&str] = &[
    "CHUNK_SIZE",
    "PROVE_CONCURRENCY",
    "VK_VERIFICATION",
    "MLE_VK_MAP",
    "MLE_VK_ROOT",
];

#[derive(Clone, Parser)]
pub struct ProverArgs {
    /// Log2 of the stacked trace height the chain proves at [default: 23, the only height
    /// whitelist mode accepts]
    #[clap(long, value_name = "N")]
    pub log_stacked_height: Option<usize>,

    /// Emulate with the ELF's AOT-compiled code. The first run for an ELF generates its crates and
    /// builds a helper binary in the AOT cache, $PICO_AOT_CACHE or `~/.pico/aot`, which takes
    /// minutes; later runs reuse it, and every ELF's helper shares one build of Pico's crates. The
    /// cache can be deleted between runs. Pico comes from this CLI's release, or from the checkout
    /// at $PICO_SOURCE
    #[clap(long)]
    pub aot: bool,
}

impl ProverArgs {
    /// For proving: read and echo every variable in [`MAPPED_ENV`], then warn about any the prover
    /// reads itself.
    pub fn resolve(&self) -> Result<ProverOptions> {
        #[cfg(not(feature = "aot"))]
        self.refuse_aot()?;
        let verify_keys = mapped("VK_VERIFICATION", "verify_keys", parse_bool)?;
        let whitelist = verify_keys == Some(true);
        let options = ProverOptions {
            log_stacked_height: self.log_stacked_height,
            chunk_size: mapped("CHUNK_SIZE", "chunk_size", parse_chunk_size)?,
            concurrency: mapped("PROVE_CONCURRENCY", "concurrency", |v| {
                v.parse::<NonZeroUsize>().map_err(|e| e.to_string())
            })?,
            verify_keys,
            vk_map: whitelist_mapped(whitelist, "MLE_VK_MAP", "vk_map", |v| Ok(PathBuf::from(v)))?,
            trusted_vk_root: whitelist_mapped(
                whitelist,
                "MLE_VK_ROOT",
                "trusted_vk_root",
                parse_root,
            )?,
            #[cfg(feature = "aot")]
            aot: self.aot_program()?,
        };
        warn_prover_reads();
        Ok(options)
    }

    /// For emulation, which reads the chunk size and the stacked height and no other option.
    pub fn resolve_for_execute(&self) -> Result<ProverOptions> {
        #[cfg(not(feature = "aot"))]
        self.refuse_aot()?;
        let options = ProverOptions {
            log_stacked_height: self.log_stacked_height,
            chunk_size: mapped("CHUNK_SIZE", "chunk_size", parse_chunk_size)?,
            concurrency: None,
            verify_keys: None,
            vk_map: None,
            trusted_vk_root: None,
            #[cfg(feature = "aot")]
            aot: self.aot_program()?,
        };
        warn_prover_reads();
        Ok(options)
    }

    /// The program `--aot` names, which only a helper holds: outside one, [`run`](crate::run)
    /// builds and runs the helper before any option is read.
    #[cfg(feature = "aot")]
    fn aot_program(&self) -> Result<Option<&'static AotProgram>> {
        if !self.aot {
            return Ok(None);
        }
        let program = crate::aot_helper::program()
            .ok_or_else(|| anyhow!("`--aot` in a binary that carries no AOT program"))?;
        eprintln!(
            "aot: --aot -> aot(the program generated from the ELF with SHA-256 {})",
            hex::encode(program.elf_sha256())
        );
        Ok(Some(program))
    }

    /// Without the `aot` feature no binary carries a program, so `--aot` needs [`run`](crate::run)
    /// to build one.
    #[cfg(not(feature = "aot"))]
    fn refuse_aot(&self) -> Result<()> {
        if self.aot {
            anyhow::bail!(
                "`--aot` runs through `cargo pico`'s entry point, `pico_cli::run`, which builds \
                 the AOT helper"
            );
        }
        Ok(())
    }
}

fn warn_prover_reads() {
    for (name, effect) in ENV_READ_BY_PROVER {
        if let Some(value) = std::env::var_os(name) {
            eprintln!(
                "warning: {name}={} is read by the prover itself and {effect}; no option \
                 overrides it",
                value.to_string_lossy()
            );
        }
    }
    for (name, reason) in ENV_NO_LONGER_READ {
        if let Some(value) = std::env::var_os(name) {
            eprintln!(
                "warning: {name}={} is no longer read: {reason}",
                value.to_string_lossy()
            );
        }
    }
}

/// What [`ProverArgs::resolve`] or [`ProverArgs::resolve_for_execute`] read. `None` leaves the
/// prover's own default.
pub struct ProverOptions {
    log_stacked_height: Option<usize>,
    chunk_size: Option<u32>,
    concurrency: Option<NonZeroUsize>,
    verify_keys: Option<bool>,
    vk_map: Option<PathBuf>,
    trusted_vk_root: Option<[u32; 8]>,
    #[cfg(feature = "aot")]
    aot: Option<&'static AotProgram>,
}

impl ProverOptions {
    /// What [`build`] keygens from, and what emulation runs from without keygen, so an option both
    /// read reaches them alike.
    pub fn builder(&self, elf: &[u8]) -> ProverBuilder {
        let mut builder = Prover::builder(elf);
        if let Some(n) = self.log_stacked_height {
            builder = builder.log_stacked_height(n);
        }
        if let Some(n) = self.chunk_size {
            builder = builder.chunk_size(n);
        }
        if let Some(n) = self.concurrency {
            builder = builder.concurrency(n);
        }
        if let Some(on) = self.verify_keys {
            builder = builder.verify_keys(on);
        }
        if let Some(path) = &self.vk_map {
            builder = builder.vk_map(path);
        }
        if let Some(root) = self.trusted_vk_root {
            builder = builder.trusted_vk_root(root);
        }
        #[cfg(feature = "aot")]
        if let Some(program) = self.aot {
            builder = builder.aot(program);
        }
        builder
    }
}

/// Keygen, then say what the prover resolved to, defaults included.
pub fn build(builder: ProverBuilder) -> Result<Prover> {
    let prover = builder.build()?;
    eprintln!(
        "prover: log_stacked_height {}, chunk_size {}, concurrency {}, verify_keys {}",
        prover.log_stacked_height(),
        prover.chunk_size(),
        prover.concurrency(),
        prover.verify_keys()
    );
    #[cfg(feature = "aot")]
    if let Some(workers) = prover.emulation_workers() {
        eprintln!("prover: aot, {workers} emulation worker(s)");
    }
    Ok(prover)
}

/// Read `name`, echoed on stderr as `env: NAME=raw -> setter(value)` or `env: NAME not set`.
pub(crate) fn mapped<T: Debug>(
    name: &str,
    setter: &str,
    parse: impl FnOnce(&str) -> Result<T, String>,
) -> Result<Option<T>> {
    let Some(raw) = std::env::var_os(name) else {
        eprintln!("env: {name} not set");
        return Ok(None);
    };
    let raw = raw
        .into_string()
        .map_err(|raw| anyhow!("{name}={}: not UTF-8", raw.to_string_lossy()))?;
    let value = parse(&raw).map_err(|e| anyhow!("{name}={raw}: {e}"))?;
    eprintln!("env: {name}={raw} -> {setter}({value:?})");
    Ok(Some(value))
}

/// The prover refuses a whitelist outside whitelist mode, so a whitelist variable left in the
/// environment would otherwise stop every proof made outside it.
fn whitelist_mapped<T: Debug>(
    whitelist: bool,
    name: &str,
    setter: &str,
    parse: impl FnOnce(&str) -> Result<T, String>,
) -> Result<Option<T>> {
    if whitelist {
        return mapped(name, setter, parse);
    }
    match std::env::var_os(name) {
        Some(raw) => eprintln!(
            "env: {name}={} ignored: only whitelist mode reads it, and VK_VERIFICATION is not \
             `true`",
            raw.to_string_lossy()
        ),
        None => eprintln!("env: {name} not set"),
    }
    Ok(None)
}

fn parse_chunk_size(value: &str) -> Result<u32, String> {
    value.parse::<u32>().map_err(|e| e.to_string())
}

/// Strict, because a misspelt `true` read as `false` would silently prove in the other mode.
fn parse_bool(value: &str) -> Result<bool, String> {
    if value.eq_ignore_ascii_case("true") {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") {
        Ok(false)
    } else {
        Err("expected `true` or `false`".into())
    }
}

/// Eight limbs separated by spaces or commas, as `mle_vk_root.txt` publishes the root.
fn parse_root(value: &str) -> Result<[u32; 8], String> {
    let limbs = value
        .split([' ', ','])
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().map_err(|e| format!("limb `{s}`: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    limbs
        .try_into()
        .map_err(|limbs: Vec<u32>| format!("expected 8 limbs, got {}", limbs.len()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_root_parses_in_either_separator() {
        let root = [1, 2, 3, 4, 5, 6, 7, 8];
        assert_eq!(parse_root("1 2 3 4 5 6 7 8"), Ok(root));
        assert_eq!(parse_root("1,2,3,4,5,6,7,8"), Ok(root));
        assert!(parse_root("1 2 3").is_err());
        assert!(parse_root("1 2 3 4 5 6 7 x").is_err());
    }

    #[cfg(not(feature = "aot"))]
    #[test]
    fn aot_without_the_feature_is_refused_rather_than_ignored() {
        let args = ProverArgs::parse_from(["prove", "--aot"]);
        for resolved in [args.resolve(), args.resolve_for_execute()] {
            let error = resolved.err().expect("`--aot` refused").to_string();
            assert!(error.contains("`pico_cli::run`"), "{error}");
        }
    }

    #[test]
    fn only_true_and_false_are_booleans() {
        assert_eq!(parse_bool("TRUE"), Ok(true));
        assert_eq!(parse_bool("false"), Ok(false));
        assert!(parse_bool("1").is_err());
        assert!(parse_bool("yes").is_err());
    }
}
