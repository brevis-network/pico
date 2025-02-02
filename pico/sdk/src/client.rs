use std::{path::PathBuf, u8};

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
    emulator::riscv::stdin::EmulatorStdin,
    instances::{
        compiler_v2::onchain_circuit::{
            gnark::builder::OnchainVerifierCircuit, stdin::OnchainStdin, utils::build_gnark_config,
        },
        configs::riscv_config::StarkConfig as RiscvBBSC,
    },
    machine::{machine::MachineBehavior, proof::MetaProof},
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
};

pub struct SDKProverClient {
    inputs: Vec<u8>,
    riscv: RiscvProver<BabyBearPoseidon2, Program>,
    convert: ConvertProver<BabyBearPoseidon2, BabyBearPoseidon2>,
    combine: CombineProver<BabyBearPoseidon2, BabyBearPoseidon2>,
    compress: CompressProver<BabyBearPoseidon2, BabyBearPoseidon2>,
    embed: EmbedProver<BabyBearPoseidon2, BabyBearBn254Poseidon2, Vec<u8>>,
}

impl SDKProverClient {
    pub fn new(elf: &[u8], inputs: &[u8]) -> SDKProverClient {
        let riscv =
            RiscvProver::new_initial_prover((RiscvBBSC::new(), elf), Default::default(), None);
        let convert = ConvertProver::new_with_prev(&riscv, Default::default(), None);
        let combine = CombineProver::new_with_prev(&convert, Default::default(), None);
        let compress = CompressProver::new_with_prev(&combine, Default::default(), None);
        let embed =
            EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, Default::default(), None);

        Self {
            inputs: inputs.to_vec(),
            riscv,
            convert,
            combine,
            compress,
            embed,
        }
    }

    fn get_stdin(inputs: &[u8]) -> EmulatorStdin<Program, Vec<u8>> {
        let mut stdin_builder = EmulatorStdin::<Program, Vec<u8>>::new_builder();
        stdin_builder.write_slice(inputs);
        stdin_builder.finalize()
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
        let stdin: EmulatorStdin<Program, Vec<u8>> = Self::get_stdin(&self.inputs);
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
        build_gnark_config(constraints, witness, output);

        Ok((riscv_proof, proof))
    }

    /// prove and verify riscv program. default not include convert, combine, compress, embed
    pub fn prove_fast(&self) -> Result<MetaProof<BabyBearPoseidon2>, Error> {
        let stdin: EmulatorStdin<Program, Vec<u8>> = Self::get_stdin(&self.inputs);
        let proof = self.riscv.prove(stdin.clone());
        info!("riscv_prover prove success");
        if !self.riscv.verify(&proof) {
            return Err(Error::msg("riscv_prover verify failed"));
        }
        println!("riscv_prover proof verify success");
        Ok(proof)
    }
}
