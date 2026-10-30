use clap::{Parser, ValueEnum};

use super::embed::EmbeddedProgram;

/// Proving step for the single-node MLE/WHIR prover. All three are wired (GPU only for the two
/// recursion steps): `riscv` = Phase-1 chunk proofs, `convert` = the riscv pipeline with the
/// streaming convert stage spliced in, `combine` = convert plus the scheduler's aggregation tree,
/// reduced to one complete root proof and verified.
#[derive(ValueEnum, Clone, Copy, Debug, PartialEq, Eq)]
#[clap(rename_all = "lowercase")]
pub enum Step {
    Riscv,
    Convert,
    Combine,
}

/// CLI / env config for the single-node MLE/WHIR prover (KoalaBear).
///
/// The MLE backend is KoalaBear-only by design, so there is no `--field` knob.
#[derive(Parser, Debug, Clone)]
#[clap(about = "single-node MLE/WHIR prover (KoalaBear)", version = crate::VERSION)]
pub struct MleSingleNodeConfig {
    /// Proving step: `riscv` | `convert` | `combine`. The latter two require `cuda`.
    #[clap(long, value_enum, env = "MLE_STEP", default_value = "riscv")]
    pub step: Step,

    /// ELF to run: `fib` | `reth`.
    #[clap(long, env = "MLE_ELF", default_value = "fib")]
    pub elf: String,

    /// Program input: fibonacci sequence length, or the reth block number when `--elf reth`
    /// (171 / 188 / 239 / 240 / 246 are aliases for the five long-standing fixtures).
    #[clap(long, env = "MLE_N", default_value = "10")]
    pub n: u32,

    /// Number of GPU cards. Each card gets two prover threads -- one for riscv, one for the
    /// recursion layers, or a single thread serving both under `MLE_RECURSION_LANE=0` -- and its
    /// own machine set (device-resident keys); prepared chunks are host-side, so any card drains
    /// them from one shared lane. Must not exceed the visible device count.
    #[clap(long, env = "PROVER_COUNT", default_value = "1")]
    pub prover_count: usize,

    /// `log_stacked_height` baked into the VK at keygen; must be >= the largest
    /// trace log-height. Bump together with `CHUNK_SIZE`. Defaults to the 2^22-chunk
    /// operating point (23), matching `single_node_mle.sh`.
    #[clap(long, env = "MLE_LOG_STACKED_HEIGHT", default_value = "23")]
    pub log_stacked_height: usize,

    /// Set by [`super::embed`] only: the program and whitelist come from the caller instead of
    /// `--elf` and the `VK_VERIFICATION` / `MLE_VK_MAP` / `MLE_VK_ROOT` environment.
    #[clap(skip)]
    pub embedded: Option<EmbeddedProgram>,
}
