use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use clap::{Parser, ValueEnum};
use pico_prover::{Phase, Proof, ProveError, ProverBuilder};

use crate::{
    guest::{encode_hex, GuestArgs},
    options::{self, ProverArgs},
};

#[derive(Parser)]
#[command(
    name = "prove",
    about = "Prove an ELF, verify the proof, and write it out"
)]
pub struct ProveCmd {
    #[clap(flatten)]
    guest: GuestArgs,

    #[clap(flatten)]
    prover: ProverArgs,

    /// Where the proving chain stops. `riscv` and `combine` write `proof-<phase>.pico`, `wrap`
    /// writes `wrap_constraints.json` and `wrap_groth16_witness.json`, and `convert` and `embed`
    /// write nothing
    #[clap(long, value_enum, default_value_t = PhaseArg::Combine)]
    phase: PhaseArg,

    /// Directory the proof is written to. A `riscv` proof file verifies in any process that has the
    /// ELF and proves at the same `--log-stacked-height` and mode; a `combine` one only when both
    /// processes are in whitelist mode
    #[clap(long, value_name = "DIR", default_value = "pico_out")]
    output: PathBuf,

    /// Prove through wrap to a Groth16 proof for the on-chain verifier, with gnark from
    /// $PICO_GNARK_BIN or $PICO_GNARK_IMAGE. The verifier accepts whitelist-mode proofs only, so
    /// this needs `VK_VERIFICATION=true`, `MLE_VK_MAP` and `MLE_VK_ROOT`. Writes the wrap files,
    /// `proof.data` and `inputs.json`
    #[clap(long, conflicts_with = "phase")]
    evm: bool,

    /// The Groth16 key directory for `--evm`: `pk`, `vk`, `ccs` and `manifest.json`, as a setup
    /// writes them [default: $PICO_GROTH16_KEYS, or `<output>/groth16` with `--setup`]. Never
    /// downloaded
    #[clap(long, value_name = "DIR", requires = "evm")]
    keys: Option<PathBuf>,

    /// Run a Groth16 setup for the wrap circuit into the key directory first, which also writes
    /// `Groth16Verifier.sol`. An operator action, not a first-run step: the setup's randomness is
    /// known to whoever runs it, so its keys are for testing, not for a deployed verifier
    #[clap(long, requires = "evm")]
    setup: bool,

    #[clap(long, hide = true)]
    fast: bool,

    #[clap(long, hide = true, num_args = 0..=1, default_missing_value = "")]
    field: Option<String>,
}

/// [`Phase`], as a value on the command line.
#[derive(Clone, Copy, ValueEnum)]
enum PhaseArg {
    Riscv,
    Convert,
    Combine,
    #[cfg_attr(not(feature = "multi-field-transcript"), value(hide = true))]
    Embed,
    #[cfg_attr(not(feature = "multi-field-transcript"), value(hide = true))]
    Wrap,
}

impl From<PhaseArg> for Phase {
    fn from(phase: PhaseArg) -> Self {
        match phase {
            PhaseArg::Riscv => Phase::Riscv,
            PhaseArg::Convert => Phase::Convert,
            PhaseArg::Combine => Phase::Combine,
            PhaseArg::Embed => Phase::Embed,
            PhaseArg::Wrap => Phase::Wrap,
        }
    }
}

impl ProveCmd {
    pub(crate) fn aot_elf(&self) -> Option<&Path> {
        self.prover.aot.then_some(self.guest.elf.as_path())
    }

    pub fn run(&self) -> Result<()> {
        self.refuse_removed_flags()?;
        if self.evm {
            return self.run_evm();
        }

        let phase = Phase::from(self.phase);
        // Checked before keygen, which is otherwise spent before the prover refuses the phase.
        phase.ensure_available().map_err(reinstall_hint)?;

        let builder = self.builder()?;
        if !builder.whitelist_mode() {
            outside_whitelist_mode(phase);
        }
        let mut prover = options::build(builder)?;
        if matches!(phase, Phase::Riscv | Phase::Combine | Phase::Wrap) {
            self.create_output()?;
        }
        let proof = prover.prove_to(self.guest.stdin(), phase)?;

        report(&proof, false);
        match phase {
            Phase::Riscv | Phase::Combine => {
                let path = self.output.join(format!("proof-{phase}.pico"));
                proof.write(&path)?;
                report_written(&path)?;
            }
            Phase::Wrap => write_wrap(&proof, &self.output)?,
            Phase::Convert | Phase::Embed => {
                eprintln!("note: a {phase} proof has no file form; nothing was written")
            }
        }
        Ok(())
    }

    /// The options from flags and the environment, echoed, then the ELF.
    fn builder(&self) -> Result<ProverBuilder> {
        let options = self.prover.resolve()?;
        let elf = self.guest.read_elf()?;
        Ok(options.builder(&elf))
    }

    fn create_output(&self) -> Result<()> {
        std::fs::create_dir_all(&self.output)
            .with_context(|| format!("cannot create `{}`", self.output.display()))
    }

    fn refuse_removed_flags(&self) -> Result<()> {
        if self.fast {
            bail!(
                "`--fast` has been removed: the RISC-V phase is full-security, not a faster proof. \
                 Use `--phase riscv` to stop after it"
            );
        }
        if self.field.is_some() {
            bail!("`--field` has been removed: proving is KoalaBear-only. Drop the flag");
        }
        Ok(())
    }

    /// `--evm`: prove to wrap in whitelist mode, then to Groth16 with gnark.
    ///
    /// Everything that can be refused is refused before keygen, which costs minutes: no gnark, no
    /// keys, a directory that is not a key set, a setup over an existing one, and a mode the
    /// on-chain verifier is not set up for.
    #[cfg(feature = "multi-field-transcript")]
    fn run_evm(&self) -> Result<()> {
        use crate::{
            groth16::{
                self, Gnark, Keys, WrapFiles, INPUTS_FILE, KEYS_ENV, MANIFEST_FILE, PROOF_FILE,
                VERIFIER_FILE,
            },
            options::mapped,
        };

        let gnark = Gnark::from_env()?;
        let dir = match &self.keys {
            Some(dir) => Some(dir.clone()),
            None => mapped(KEYS_ENV, "keys", |v| Ok(PathBuf::from(v)))?,
        };
        let keys = if self.setup {
            Keys::fresh(dir.unwrap_or_else(|| self.output.join("groth16")))?
        } else {
            let dir = dir.ok_or_else(|| {
                anyhow::anyhow!(
                    "`--evm` proves with a Groth16 key directory: pass `--keys DIR` or set \
                     {KEYS_ENV}, or `--setup` to make one"
                )
            })?;
            Keys::existing(dir)?
        };

        let builder = self.builder()?;
        if !builder.whitelist_mode() {
            bail!(
                "`--evm` proves in whitelist mode only: the on-chain verifier is set up for the \
                 wrap circuit that bakes in the whitelist root. Set `VK_VERIFICATION=true`, \
                 `MLE_VK_MAP` and `MLE_VK_ROOT`"
            );
        }
        self.create_output()?;
        let mut prover = options::build(builder)?;
        let bundle = prover.prove_evm(self.guest.stdin())?;
        bundle.write_to(&self.output)?;
        let wrap = WrapFiles {
            constraints: self.output.join(pico_prover::WRAP_CONSTRAINTS_FILE),
            witness: self.output.join(pico_prover::WRAP_WITNESS_FILE),
        };

        if self.setup {
            gnark.setup(&wrap, &keys)?;
            eprintln!(
                "note: `--setup` made these keys on this machine, which knew the setup's \
                 randomness: they are for testing, and a verifier deployed for them proves nothing"
            );
        }
        let proof_path = self.output.join(PROOF_FILE);
        let proof = gnark.prove(&wrap, &keys, &proof_path)?;
        // gnark read its public inputs from the witness; the bundle has them from the proof.
        let expected = [
            bundle.program_id().vkey_hash(),
            bundle.committed_value_digest(),
        ];
        if proof.public_inputs() != expected {
            let [vkey, digest] = proof.public_inputs();
            bail!(
                "gnark proved public inputs 0x{} and 0x{}, and the proof's are 0x{} and 0x{}: the \
                 witness in `{}` is not this proof's",
                encode_hex(&vkey),
                encode_hex(&digest),
                encode_hex(&expected[0]),
                encode_hex(&expected[1]),
                self.output.display()
            );
        }
        let inputs = self.output.join(INPUTS_FILE);
        groth16::write_inputs(&inputs, expected[0], bundle.committed().as_bytes(), &proof)?;

        report(bundle.proof(), true);
        for path in [&wrap.constraints, &wrap.witness] {
            report_written(path)?;
        }
        if self.setup {
            for file in [MANIFEST_FILE, VERIFIER_FILE] {
                report_written(&keys.path(file))?;
            }
        }
        report_written(&proof_path)?;
        report_written(&inputs)?;
        Ok(())
    }

    #[cfg(not(feature = "multi-field-transcript"))]
    fn run_evm(&self) -> Result<()> {
        Phase::Wrap.ensure_available().map_err(reinstall_hint)
    }
}

/// The prover's refusal of a phase this build lacks, with the fix: the prover names the feature,
/// but what the user does about it is reinstall `cargo pico`.
fn reinstall_hint(error: ProveError) -> anyhow::Error {
    let ProveError::FeatureMissing { phase, feature } = &error else {
        return error.into();
    };
    let context = format!(
        "this cargo-pico was built without its default `{feature}` feature, so it cannot prove to \
         `{phase}`: reinstall it without `--no-default-features`"
    );
    anyhow::Error::from(error).context(context)
}

/// What a proof of `phase` made outside whitelist mode cannot be used for. The options decide it,
/// so it is said before keygen rather than after the proof.
fn outside_whitelist_mode(phase: Phase) {
    match phase {
        // A fresh process refuses a combine file made outside whitelist mode whichever mode it is
        // in: outside it, it has no honest recursion key, and inside it, the modes differ.
        Phase::Combine => eprintln!(
            "note: no other process can verify a combine proof made outside whitelist mode. \
             `VK_VERIFICATION=true`, `MLE_VK_MAP` and `MLE_VK_ROOT`, at the default stacked \
             height, make one that can; `--phase riscv` makes a file another process verifies \
             from the ELF at the same height, but it proves each chunk, not one complete execution"
        ),
        Phase::Wrap => eprintln!(
            "warning: outside whitelist mode the wrap circuit pins no whitelist root, so no \
             deployed verifier accepts a proof of it; this output is for testing"
        ),
        Phase::Riscv | Phase::Convert | Phase::Embed => {}
    }
}

/// `groth16`: the wrap proof went on to a Groth16 proof, which gnark verified before writing it.
fn report(proof: &Proof, groth16: bool) {
    // The wrap phase compiles a circuit and its witness from the verified embed proof; the Groth16
    // proof of that circuit is made outside this prover, by gnark under `--evm`.
    let reached = match (proof.phase(), groth16) {
        (Phase::Wrap, true) => {
            "embed, built the wrap circuit and witness, and gnark proved and verified them to \
             Groth16"
                .into()
        }
        (Phase::Wrap, false) => {
            "embed, and built the wrap circuit and witness (no Groth16 proof)".into()
        }
        (phase, _) => phase.to_string(),
    };
    // One chunk proof per emulation record; the deferred split adds records after the guest halts,
    // so this runs ahead of the chunk count `execute` reports.
    println!(
        "proved and verified to {reached}: {} chunk proof(s), {} proof(s)",
        proof
            .chunk_count()
            .map_or_else(|| "unknown".into(), |n| n.to_string()),
        proof.proof_count()
    );
    let committed = proof.committed();
    println!(
        "committed ({} byte(s)): {}",
        committed.as_bytes().len(),
        encode_hex(committed.as_bytes())
    );
    println!(
        "committed_value_digest: {}",
        encode_hex(&proof.committed_value_digest())
    );
    if !proof.binds_complete_execution() {
        eprintln!(
            "note: a {} proof binds each chunk, not one complete execution; prove to combine for \
             that",
            proof.phase()
        );
    }
    // Whitelist mode pads the program table before committing to it, so one ELF has a different id
    // in each mode.
    let mode = if proof.verify_keys() {
        "whitelist mode"
    } else {
        "outside whitelist mode, so not the id an on-chain verifier pins"
    };
    println!("program id ({mode}): {}", proof.program_id());
}

fn report_written(path: &Path) -> Result<()> {
    let size = std::fs::metadata(path)
        .with_context(|| format!("cannot stat `{}`", path.display()))?
        .len();
    println!("wrote {} ({size} bytes)", path.display());
    Ok(())
}

#[cfg(feature = "multi-field-transcript")]
fn write_wrap(proof: &Proof, dir: &Path) -> Result<()> {
    let constraints = dir.join(pico_prover::WRAP_CONSTRAINTS_FILE);
    let witness = dir.join(pico_prover::WRAP_WITNESS_FILE);
    proof.write_wrap_artifacts(&constraints, &witness)?;
    report_written(&constraints)?;
    report_written(&witness)?;
    Ok(())
}

#[cfg(not(feature = "multi-field-transcript"))]
fn write_wrap(_proof: &Proof, _dir: &Path) -> Result<()> {
    Phase::Wrap.ensure_available().map_err(reinstall_hint)
}
