use crate::command::execute_command;
use anyhow::{Error, Result};
use log::{debug, info};
use p3_baby_bear::BabyBear;
use p3_koala_bear::KoalaBear;
use pico_vm::{
    compiler::riscv::program::Program,
    configs::{
        config::StarkGenericConfig,
        field_config::{BabyBearBn254, KoalaBearBn254},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    emulator::stdin::EmulatorStdinBuilder,
    instances::{
        chiptype::recursion_chiptype::RecursionChipType,
        compiler::{
            onchain_circuit::{
                gnark::builder::OnchainVerifierCircuit,
                stdin::OnchainStdin,
                utils::{build_gnark_config, generate_contract_inputs, save_embed_proof_data},
            },
            shapes::{recursion_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
            vk_merkle::vk_verification_enabled,
        },
        configs::{embed_config::BabyBearBn254Poseidon2, embed_kb_config::KoalaBearBn254Poseidon2},
    },
    machine::{keys::BaseVerifyingKey, machine::MachineBehavior, proof::MetaProof},
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
};
use std::{path::Path, process::Command};

#[macro_export]
macro_rules! create_sdk_prove_client {
    ($client_name:ident, $sc:ty, $bn254_sc:ty, $fc:ty, $field_type: ty) => {
        pub struct $client_name {
            riscv: RiscvProver<$sc, Program>,
            convert: ConvertProver<$sc, $sc>,
            combine: CombineProver<$sc, $sc>,
            compress: CompressProver<$sc, $sc>,
            embed: EmbedProver<$sc, $bn254_sc, Vec<u8>>,
        }

        impl $client_name {
            pub fn new(elf: &[u8]) -> Self {
                let vk_verification = vk_verification_enabled();
                debug!("VK_VERIFICATION in prover client: {}", vk_verification);
                let (riscv, convert, combine, compress, embed) = if vk_verification {
                    let riscv_shape_config = RiscvShapeConfig::<$field_type>::default();
                    let recursion_shape_config = RecursionShapeConfig::<
                        $field_type,
                        RecursionChipType<$field_type>,
                    >::default();
                    let riscv = RiscvProver::new_initial_prover(
                        (<$sc>::new(), elf),
                        Default::default(),
                        Some(riscv_shape_config),
                    );
                    let convert = ConvertProver::new_with_prev(
                        &riscv,
                        Default::default(),
                        Some(recursion_shape_config),
                    );
                    let recursion_shape_config = RecursionShapeConfig::<
                        $field_type,
                        RecursionChipType<$field_type>,
                    >::default();
                    let combine = CombineProver::new_with_prev(
                        &convert,
                        Default::default(),
                        Some(recursion_shape_config),
                    );
                    let compress = CompressProver::new_with_prev(&combine, (), None);
                    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);
                    (riscv, convert, combine, compress, embed)
                } else {
                    let riscv =
                        RiscvProver::new_initial_prover((<$sc>::new(), elf), Default::default(), None);
                    let convert = ConvertProver::new_with_prev(&riscv, Default::default(), None);
                    let combine = CombineProver::new_with_prev(&convert, Default::default(), None);
                    let compress = CompressProver::new_with_prev(&combine, (), None);
                    let embed = EmbedProver::<_, _, Vec<u8>>::new_with_prev(&compress, (), None);
                    (riscv, convert, combine, compress, embed)
                };

                Self {
                    riscv,
                    convert,
                    combine,
                    compress,
                    embed,
                }
            }

            pub fn new_stdin_builder(&self) -> EmulatorStdinBuilder<Vec<u8>> {
                EmulatorStdinBuilder::default()
            }

            pub fn riscv_vk(&self) -> &BaseVerifyingKey<$sc> {
                self.riscv.vk()
            }

            /// prove and serialize embed proof, which provided to next step gnark verifier.
            /// the constraints.json and groth16_witness.json will be generated in output dir.
            pub fn prove(
                &self,
                stdin: EmulatorStdinBuilder<Vec<u8>>,
            ) -> Result<(MetaProof<$sc>, MetaProof<$bn254_sc>), Error> {
                let stdin = stdin.finalize();
                let riscv_proof = self.riscv.prove(stdin);
                let _riscv_vk = self.riscv_vk();
                // if !self.riscv.verify(&riscv_proof.clone(), riscv_vk) {
                //     return Err(Error::msg("verify riscv proof failed"));
                // }
                let proof = self.convert.prove(riscv_proof.clone());
                // if !self.convert.verify(&proof, riscv_vk) {
                //     return Err(Error::msg("verify convert proof failed"));
                // }
                let proof = self.combine.prove(proof);
                // if !self.combine.verify(&proof, riscv_vk) {
                //     return Err(Error::msg("verify combine proof failed"));
                // }
                let proof = self.compress.prove(proof);
                // if !self.compress.verify(&proof, riscv_vk) {
                //     return Err(Error::msg("verify compress proof failed"));
                // }
                let proof = self.embed.prove(proof);
                // if !self.embed.verify(&proof, riscv_vk) {
                //     return Err(Error::msg("verify embed proof failed"));
                // }
                Ok((riscv_proof, proof))
            }

            /// verify the riscv and embed proof
            pub fn verify(
                &self,
                proof: &(MetaProof<$sc>, MetaProof<$bn254_sc>),
            ) -> Result<(), Error> {
                let riscv_vk = self.riscv_vk();
                if !self.riscv.verify(&proof.0, riscv_vk) {
                    return Err(Error::msg("verify riscv proof failed"));
                }
                if !self.embed.verify(&proof.1, riscv_vk) {
                    return Err(Error::msg("verify embed proof failed"));
                }
                Ok(())
            }

            /// emulate the program and return the cycles
            pub fn emulate(
                &self,
                stdin: EmulatorStdinBuilder<Vec<u8>>,
            ) -> (u64, Vec<u8>) {
                let stdin = stdin.finalize();
                self.riscv.emulate(stdin)
            }

            pub fn write_onchain_data(
                &self,
                outdir: impl AsRef<Path>,
                riscv_proof: &MetaProof<$sc>,
                embed_proof: &MetaProof<$bn254_sc>,
            ) -> Result<()> {
                let onchain_stdin = OnchainStdin {
                    machine: self.embed.machine.base_machine().clone(),
                    vk: embed_proof.vks().first().unwrap().clone(),
                    proof: embed_proof.proofs().first().unwrap().clone(),
                    flag_complete: true,
                };
                let (constraints, witness) =
                    OnchainVerifierCircuit::<$fc, $bn254_sc>::build(&onchain_stdin);
                save_embed_proof_data(&riscv_proof, &embed_proof, &outdir)?;
                build_gnark_config(constraints, witness, &outdir);
                Ok(())
            }

            /// prove and verify riscv program. default not include convert, combine, compress, embed
            pub fn prove_fast(
                &self,
                stdin: EmulatorStdinBuilder<Vec<u8>>,
            ) -> Result<MetaProof<$sc>, Error> {
                let stdin = stdin.finalize();
                info!("stdin length: {}", stdin.inputs.len());
                let proof = self.riscv.prove(stdin);
                let riscv_vk = self.riscv_vk();
                info!("riscv_prover prove success");
                if !self.riscv.verify(&proof, riscv_vk) {
                    return Err(Error::msg("riscv_prover verify failed"));
                }
                info!("riscv_prover proof verify success");
                Ok(proof)
            }

            /// prove and generate gnark proof and contract inputs. must install docker first
            pub fn prove_evm(
                &self,
                stdin: EmulatorStdinBuilder<Vec<u8>>,
                need_setup: bool,
                output: impl AsRef<Path>,
                field_type: &str,
            ) -> Result<(), Error> {
                let output = output.as_ref();
                // let vk_verification = vk_verification_enabled();
                // if !vk_verification {
                //     return Err(Error::msg("VK_VERIFICATION must be set to true in evm proof"));
                // }
                let (riscv_proof, embed_proof) = self.prove(stdin)?;
                self.write_onchain_data(output, &riscv_proof, &embed_proof)?;
                let field_name = match field_type {
                    "kb" => {
                        "koalabear"
                    }
                    "bb" => {
                        "babybear"
                    }
                    _ => {
                        return Err(Error::msg("field type not supported"));
                    }
                };
                if need_setup {
                    let mut setup_cmd = Command::new("sh");
                    setup_cmd.arg("-c")
                        .arg(format!("docker run --rm -v {}:/data brevishub/pico_gnark_cli:1.1 /pico_gnark_cli -field {} -cmd setup -sol ./data/Groth16Verifier.sol", output.display(), field_name));
                    execute_command(setup_cmd);
                }

                let mut prove_cmd = Command::new("sh");
                prove_cmd.arg("-c")
                    .arg(format!("docker run --rm -v {}:/data brevishub/pico_gnark_cli:1.1 /pico_gnark_cli -field {} -cmd prove -sol ./data/Groth16Verifier.sol", output.display(), field_name));

                execute_command(prove_cmd);
                generate_contract_inputs::<$fc>(output.clone())?;
                Ok(())
            }
        }
    };
}

create_sdk_prove_client!(
    BabyBearProverClient,
    BabyBearPoseidon2,
    BabyBearBn254Poseidon2,
    BabyBearBn254,
    BabyBear
);
create_sdk_prove_client!(
    KoalaBearProverClient,
    KoalaBearPoseidon2,
    KoalaBearBn254Poseidon2,
    KoalaBearBn254,
    KoalaBear
);

pub use KoalaBearProverClient as DefaultProverClient;
