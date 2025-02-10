use std::{cell::RefCell, path::PathBuf, process::Command, rc::Rc};

use crate::command::execute_command;
use anyhow::{Error, Ok};
use log::info;
use p3_baby_bear::BabyBear;
use pico_vm::{
    compiler::riscv::program::Program,
    configs::{
        config::StarkGenericConfig,
        field_config::bb_bn254::BabyBearBn254,
        stark_config::{
            bb_bn254_poseidon2::BabyBearBn254Poseidon2, bb_poseidon2::BabyBearPoseidon2,
        },
    },
    emulator::stdin::{EmulatorStdin, EmulatorStdinBuilder},
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            onchain_circuit::{
                gnark::builder::OnchainVerifierCircuit,
                stdin::OnchainStdin,
                utils::{build_gnark_config, generate_contract_inputs},
            },
            shapes::{compress_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
        },
        configs::riscv_config::StarkConfig as RiscvBBSC,
    },
    machine::{machine::MachineBehavior, proof::MetaProof},
    proverchain::{
        CombineVkProver, CompressVkProver, ConvertProver, EmbedVkProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
};

pub struct ProverVkClient {
    riscv: RiscvProver<BabyBearPoseidon2, Program>,
    convert: ConvertProver<BabyBearPoseidon2, BabyBearPoseidon2>,
    combine: CombineVkProver<BabyBearPoseidon2, BabyBearPoseidon2>,
    compress: CompressVkProver<BabyBearPoseidon2, BabyBearPoseidon2>,
    embed: EmbedVkProver<BabyBearPoseidon2, BabyBearBn254Poseidon2, Vec<u8>>,
    stdin_builder: Rc<RefCell<EmulatorStdinBuilder<Vec<u8>>>>,
}

impl ProverVkClient {
    pub fn new(elf: &[u8]) -> ProverVkClient {
        let riscv_shape_config = RiscvShapeConfig::<BabyBear>::default();
        let recursion_shape_config =
            RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear>>::default();
        let riscv = RiscvProver::new_initial_prover(
            (RiscvBBSC::new(), elf),
            Default::default(),
            Some(riscv_shape_config),
        );
        let convert =
            ConvertProver::new_with_prev(&riscv, Default::default(), Some(recursion_shape_config));
        let recursion_shape_config =
            RecursionShapeConfig::<BabyBear, RecursionChipType<BabyBear>>::default();
        let combine = CombineVkProver::new_with_prev(
            &convert,
            Default::default(),
            Some(recursion_shape_config),
        );
        let compress = CompressVkProver::new_with_prev(&combine, (), None);
        let embed = EmbedVkProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);
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

    /// prove and generate gnark proof and contract inputs. must install docker first
    pub fn prove_evm(&self, need_setup: bool, output: PathBuf) -> Result<(), Error> {
        self.prove(output.clone())?;
        if need_setup {
            let mut setup_cmd = Command::new("sh");
            setup_cmd.arg("-c")
                .arg(format!("docker run --rm -v {}:/data liuxiaobleach657/test_vm:0.04 /pico_vm_gnark_cli -cmd setup", output.clone().display()));
            execute_command(setup_cmd);
        }

        let mut prove_cmd = Command::new("sh");
        prove_cmd.arg("-c")
            .arg(format!("docker run --rm -v {}:/data liuxiaobleach657/test_vm:0.04 /pico_vm_gnark_cli -cmd prove", output.clone().display()));

        execute_command(prove_cmd);
        generate_contract_inputs::<BabyBearBn254>(output.clone())?;
        Ok(())
    }
}
