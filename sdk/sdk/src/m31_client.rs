use std::{cell::RefCell, rc::Rc};

use anyhow::Error;
use log::info;
use pico_vm::{
    compiler::riscv::program::Program,
    configs::{config::StarkGenericConfig, stark_config::m31_poseidon2::M31Poseidon2},
    emulator::stdin::{EmulatorStdin, EmulatorStdinBuilder},
    machine::proof::MetaProof,
    proverchain::{InitialProverSetup, MachineProver, RiscvProver},
};

/// Client for proving riscv program over M31.
pub struct M31RiscvProverClient {
    riscv: RiscvProver<M31Poseidon2, Program>,
    stdin_builder: Rc<RefCell<EmulatorStdinBuilder<Vec<u8>>>>,
}

impl M31RiscvProverClient {
    pub fn new(elf: &[u8]) -> M31RiscvProverClient {
        let riscv =
            RiscvProver::new_initial_prover((M31Poseidon2::new(), elf), Default::default(), None);
        let stdin_builder = Rc::new(RefCell::new(
            EmulatorStdin::<Program, Vec<u8>>::new_builder(),
        ));

        Self {
            riscv,
            stdin_builder,
        }
    }

    pub fn get_stdin_builder(&self) -> Rc<RefCell<EmulatorStdinBuilder<Vec<u8>>>> {
        Rc::clone(&self.stdin_builder)
    }

    /// prove and verify riscv program. default not include convert, combine, compress, embed
    pub fn prove_fast(&self) -> Result<MetaProof<M31Poseidon2>, Error> {
        let stdin = self.stdin_builder.borrow().clone().finalize();
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
