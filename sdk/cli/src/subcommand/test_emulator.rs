use anyhow::Result;
use clap::Parser;
use log::debug;
use pico_vm::{
    compiler::riscv::compiler::{Compiler, SourceType},
    configs::{config::StarkGenericConfig, stark_config::KoalaBearPoseidon2},
    emulator::{opts::EmulatorOpts, riscv::riscv_emulator::RiscvEmulator},
};
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
            "Found signature region: begin=0x{:016x}, end=0x{:016x}",
            begin, end
        );

        // Use emulator directly (bypass prover/chip setup which doesn't support RV64 opcodes yet)
        type F = <KoalaBearPoseidon2 as StarkGenericConfig>::Val;

        let program = Compiler::new(SourceType::RISCV, &elf_bytes)
            .map_err(|e| anyhow::anyhow!("Failed to compile ELF: {}", e))?
            .compile();

        let mut emulator = RiscvEmulator::new_single::<F>(program, EmulatorOpts::default(), None);

        loop {
            let mut batch_records = vec![];
            let result = emulator.emulate_batch(&mut |record| batch_records.push(record));

            match result {
                Ok(report) => {
                    if report.done {
                        break;
                    }
                }
                Err(err) => {
                    log::error!(
                        "test_emulator: emulate_batch failed: {:?}, will still try to collect signatures",
                        err
                    );
                    break;
                }
            }
        }

        let signatures = emulator.collect_signatures(begin, end);

        // Write signatures to file
        // signature-granularity=4: each line is one 32-bit word (8 hex chars)
        let mut file = File::create(&self.signatures)?;
        for sig in signatures {
            writeln!(file, "{:08x}", sig as u32)?;
        }

        Ok(())
    }
}
