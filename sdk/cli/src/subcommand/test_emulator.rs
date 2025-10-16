use anyhow::Result;
use clap::Parser;
use log::debug;
use std::{fs::File, io::Write, path::PathBuf};

use pico_vm::compiler::riscv::disassembler::find_signature_region;

#[derive(Parser)]
#[command(
    name = "test-emulator",
    about = "Execute ELF execution and collect RISCOF signatures"
)]
pub struct TestEmulatorCmd {
    #[clap(long, help = "ELF file path")]
    elf: String,

    #[clap(long, help = "Output signature file path")]
    signatures: PathBuf,
}

impl TestEmulatorCmd {
    pub fn run(&self) -> Result<()> {
        // Read ELF bytes
        let elf_bytes = std::fs::read(&self.elf)?;

        // Parse symbols to find begin_signature and end_signature
        let (begin, end) = find_signature_region(&elf_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to parse ELF symbols: {}", e))?;

        debug!(
            "Found signature region: begin=0x{:08x}, end=0x{:08x}",
            begin, end
        );

        // Create RiscvProver directly (hard-coded to KoalaBear for RISCOF)
        use pico_vm::{
            configs::{config::StarkGenericConfig, stark_config::KoalaBearPoseidon2},
            proverchain::{InitialProverSetup, RiscvProver},
        };
        let prover = RiscvProver::new_initial_prover(
            (KoalaBearPoseidon2::new(), &elf_bytes),
            Default::default(),
            None,
        );

        // Collect signatures
        let signatures = prover.test_emulator(begin, end);

        // Write signatures to file
        let mut file = File::create(&self.signatures)?;
        for sig in signatures {
            writeln!(file, "{:08x}", sig)?;
        }

        Ok(())
    }
}
