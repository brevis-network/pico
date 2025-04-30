use anyhow::Error;
use log::info;
use pico_vm::{
    compiler::riscv::program::Program,
    configs::{config::StarkGenericConfig, stark_config::m31_poseidon2::M31Poseidon2},
    emulator::stdin::EmulatorStdinBuilder,
    machine::proof::MetaProof,
    proverchain::{InitialProverSetup, MachineProver, RiscvProver},
};

/// Client for proving riscv program over M31.
pub struct M31RiscvProverClient {
    riscv: RiscvProver<M31Poseidon2, Program>,
}

impl M31RiscvProverClient {
    pub fn new(elf: &[u8]) -> M31RiscvProverClient {
        let riscv =
            RiscvProver::new_initial_prover((M31Poseidon2::new(), elf), Default::default(), None);

        Self { riscv }
    }

    pub fn new_stdin_builder(&self) -> EmulatorStdinBuilder<Vec<u8>> {
        EmulatorStdinBuilder::default()
    }

    /// prove and verify riscv program. default not include convert, combine, compress, embed
    pub fn prove_fast(
        &self,
        stdin: EmulatorStdinBuilder<Vec<u8>>,
    ) -> Result<MetaProof<M31Poseidon2>, Error> {
        let stdin = stdin.finalize();
        info!("stdin length: {}", stdin.inputs.len());
        let proof = self.riscv.prove(stdin);
        let riscv_vk = self.riscv.vk();
        info!("riscv_prover prove success");
        if !self.riscv.verify(&proof, riscv_vk) {
            return Err(Error::msg("riscv_prover verify failed"));
        }
        info!("riscv_prover proof verify success");
        Ok(proof)
    }
}
