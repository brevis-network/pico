use std::{cell::RefCell, path::PathBuf, rc::Rc};

use crate::client_vk::ProverVkClient;
use anyhow::{Error, Ok};
use log::info;
use pico_vm::{
    compiler::riscv::program::Program,
    configs::{
        config::StarkGenericConfig,
        field_config::bb_bn254::BabyBearBn254,
        stark_config::{
            bb_bn254_poseidon2::BabyBearBn254Poseidon2, bb_poseidon2::BabyBearPoseidon2,
        },
    },
    emulator::riscv::stdin::{EmulatorStdin, EmulatorStdinBuilder},
    instances::{
        compiler::onchain_circuit::{
            gnark::builder::OnchainVerifierCircuit,
            stdin::OnchainStdin,
            utils::{build_gnark_config, generate_contract_inputs},
        },
        configs::riscv_config::StarkConfig as RiscvBBSC,
    },
    machine::{machine::MachineBehavior, proof::MetaProof},
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
};

pub enum SDKProverClient {
    Fast(ProverClient),
    ShapeConfig(ProverVkClient),
}

impl SDKProverClient {
    pub fn new(elf: &[u8], vk_verification: bool) -> Self {
        if vk_verification {
            SDKProverClient::ShapeConfig(ProverVkClient::new(elf))
        } else {
            SDKProverClient::Fast(ProverClient::new(elf))
        }
    }

    pub fn prove(
        &self,
        output: PathBuf,
    ) -> Result<
        (
            MetaProof<BabyBearPoseidon2>,
            MetaProof<BabyBearBn254Poseidon2>,
        ),
        Error,
    > {
        match self {
            SDKProverClient::Fast(client) => client.prove(output),
            SDKProverClient::ShapeConfig(client) => client.prove(output),
        }
    }

    pub fn prove_fast(&self) -> Result<MetaProof<BabyBearPoseidon2>, Error> {
        match self {
            SDKProverClient::Fast(client) => client.prove_fast(),
            SDKProverClient::ShapeConfig(client) => client.prove_fast(),
        }
    }

    pub fn prove_evm(&self, need_setup: bool, output: PathBuf) -> Result<(), Error> {
        match self {
            SDKProverClient::ShapeConfig(client) => client.prove_evm(need_setup, output),
            _ => Err(Error::msg("prove evm only support vk verification")),
        }
    }

    pub fn get_stdin_builder(&self) -> Rc<RefCell<EmulatorStdinBuilder<Vec<u8>>>> {
        match self {
            SDKProverClient::Fast(client) => client.get_stdin_builder(),
            SDKProverClient::ShapeConfig(client) => client.get_stdin_builder(),
        }
    }
}

pub struct ProverClient {
    riscv: RiscvProver<BabyBearPoseidon2, Program>,
    convert: ConvertProver<BabyBearPoseidon2, BabyBearPoseidon2>,
    combine: CombineProver<BabyBearPoseidon2, BabyBearPoseidon2>,
    compress: CompressProver<BabyBearPoseidon2, BabyBearPoseidon2>,
    embed: EmbedProver<BabyBearPoseidon2, BabyBearBn254Poseidon2, Vec<u8>>,
    stdin_builder: Rc<RefCell<EmulatorStdinBuilder<Vec<u8>>>>,
}

impl ProverClient {
    pub fn new(elf: &[u8]) -> ProverClient {
        let riscv =
            RiscvProver::new_initial_prover((RiscvBBSC::new(), elf), Default::default(), None);
        let convert = ConvertProver::new_with_prev(&riscv, Default::default(), None);
        let combine = CombineProver::new_with_prev(&convert, Default::default(), None);
        let compress = CompressProver::new_with_prev(&combine, (), None);
        let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);
        let stdin_builder = Rc::new(RefCell::new(
            EmulatorStdin::<Program, Vec<u8>>::new_builder(),
        ));

        Self {
            riscv,
            convert,
            combine,
            compress,
            embed,
            stdin_builder,
        }
    }

    pub fn get_stdin_builder(&self) -> Rc<RefCell<EmulatorStdinBuilder<Vec<u8>>>> {
        Rc::clone(&self.stdin_builder)
    }

    /// prove and serialize embed proof, which provided to next step gnark verifier.
    /// the constraints.json and groth16_witness.json will be genererated in output dir.
    pub fn prove(
        &self,
        output: PathBuf,
    ) -> Result<
        (
            MetaProof<BabyBearPoseidon2>,
            MetaProof<BabyBearBn254Poseidon2>,
        ),
        Error,
    > {
        let stdin = self.stdin_builder.borrow().clone().finalize();
        let riscv_proof = self.riscv.prove(stdin);
        if !self.riscv.verify(&riscv_proof.clone()) {
            return Err(Error::msg("verify riscv proof failed"));
        }
        let proof = self.convert.prove(riscv_proof.clone());
        if !self.convert.verify(&proof) {
            return Err(Error::msg("verify convert proof failed"));
        }
        let proof = self.combine.prove(proof);
        if !self.combine.verify(&proof) {
            return Err(Error::msg("verify combine proof failed"));
        }
        let proof = self.compress.prove(proof);
        if !self.compress.verify(&proof) {
            return Err(Error::msg("verify compress proof failed"));
        }
        let proof = self.embed.prove(proof);
        if !self.embed.verify(&proof) {
            return Err(Error::msg("verify embed proof failed"));
        }

        let onchain_stdin = OnchainStdin {
            machine: self.embed.machine.base_machine().clone(),
            vk: proof.vks().first().unwrap().clone(),
            proof: proof.proofs().first().unwrap().clone(),
            flag_complete: true,
        };
        let (constraints, witness) =
            OnchainVerifierCircuit::<BabyBearBn254, BabyBearBn254Poseidon2>::build(&onchain_stdin);
        build_gnark_config(constraints, witness, output.clone());
        generate_contract_inputs::<BabyBearBn254>(output)?;

        Ok((riscv_proof, proof))
    }

    /// prove and verify riscv program. default not include convert, combine, compress, embed
    pub fn prove_fast(&self) -> Result<MetaProof<BabyBearPoseidon2>, Error> {
        let stdin = self.stdin_builder.borrow().clone().finalize();
        println!("stdin length: {}", stdin.inputs.len());
        let proof = self.riscv.prove(stdin);
        info!("riscv_prover prove success");
        if !self.riscv.verify(&proof) {
            return Err(Error::msg("riscv_prover verify failed"));
        }
        println!("riscv_prover proof verify success");
        Ok(proof)
    }
}
