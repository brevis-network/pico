use anyhow::{Context, Error, Ok, Result};
use log::{debug, info};
use pico_vm::{
    compiler::riscv::program::Program,
    configs::{
        config::StarkGenericConfig,
        field_config::{bb_bn254::BabyBearBn254, kb_bn254::KoalaBearBn254},
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    emulator::stdin::{EmulatorStdin, EmulatorStdinBuilder},
    instances::{
        compiler::onchain_circuit::{
            gnark::builder::OnchainVerifierCircuit, stdin::OnchainStdin, utils::build_gnark_config,
        },
        configs::{embed_config::BabyBearBn254Poseidon2, embed_kb_config::KoalaBearBn254Poseidon2},
    },
    machine::{machine::MachineBehavior, proof::MetaProof},
    proverchain::{
        CombineProver, CompressProver, ConvertProver, EmbedProver, InitialProverSetup,
        MachineProver, ProverChain, RiscvProver,
    },
};
use std::{cell::RefCell, fs::File, io::Write, path::PathBuf, rc::Rc};

#[macro_export]
macro_rules! create_sdk_prove_client {
    ($client_name:ident, $sc:ty, $bn254_sc:ty, $fc:ty, $field_type: ty) => {
        pub struct $client_name {
            riscv: RiscvProver<$sc, Program>,
            convert: ConvertProver<$sc, $sc>,
            combine: CombineProver<$sc, $sc>,
            compress: CompressProver<$sc, $sc>,
            embed: EmbedProver<$sc, $bn254_sc, Vec<u8>>,
            stdin_builder: Rc<RefCell<EmulatorStdinBuilder<Vec<u8>>>>,
        }

        impl $client_name {
            pub fn new(elf: &[u8]) -> Self {
                let riscv =
                    RiscvProver::new_initial_prover((<$sc>::new(), elf), Default::default(), None);
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
            ) -> Result<(MetaProof<$sc>, MetaProof<$bn254_sc>), Error> {
                let stdin = self.stdin_builder.borrow().clone().finalize();
                let riscv_proof = self.riscv.prove(stdin);
                let riscv_vk = self.riscv.vk();
                if !self.riscv.verify(&riscv_proof.clone(), riscv_vk) {
                    return Err(Error::msg("verify riscv proof failed"));
                }
                let proof = self.convert.prove(riscv_proof.clone());
                if !self.convert.verify(&proof, riscv_vk) {
                    return Err(Error::msg("verify convert proof failed"));
                }
                let proof = self.combine.prove(proof);
                if !self.combine.verify(&proof, riscv_vk) {
                    return Err(Error::msg("verify combine proof failed"));
                }
                let proof = self.compress.prove(proof);
                if !self.compress.verify(&proof, riscv_vk) {
                    return Err(Error::msg("verify compress proof failed"));
                }
                let proof = self.embed.prove(proof);
                if !self.embed.verify(&proof, riscv_vk) {
                    return Err(Error::msg("verify embed proof failed"));
                }

                let onchain_stdin = OnchainStdin {
                    machine: self.embed.machine.base_machine().clone(),
                    vk: proof.vks().first().unwrap().clone(),
                    proof: proof.proofs().first().unwrap().clone(),
                    flag_complete: true,
                };
                let (constraints, witness) =
                    OnchainVerifierCircuit::<$fc, $bn254_sc>::build(&onchain_stdin);
                build_gnark_config(constraints, witness, output.clone());
                Ok((riscv_proof, proof))
            }

            /// prove and verify riscv program. default not include convert, combine, compress, embed
            pub fn prove_fast(&self) -> Result<MetaProof<$sc>, Error> {
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
    };
}

pub fn save_proof_data<SC: StarkGenericConfig, Bn254SC: StarkGenericConfig>(
    riscv_proof: &MetaProof<SC>,
    embed_proof: &MetaProof<Bn254SC>,
    output: PathBuf,
) -> Result<()> {
    if let Some(ref pv_stream) = riscv_proof.pv_stream {
        debug!("pv_stream is not null, storing in pico_out dir");

        let pv_stream_str = hex::encode(pv_stream);
        let pv_file_path = output.join("pv_file");

        let mut file = File::create(&pv_file_path)
            .with_context(|| format!("Failed to create file: {:?}", pv_file_path))?;
        file.write_all(pv_stream_str.as_bytes())
            .context("Failed to write pv_stream to file")?;
    }

    // Write proof to proof.json
    let proof_path = output.join("proof.json");
    let mut proof_file = File::create(&proof_path)
        .with_context(|| format!("Failed to create file: {:?}", proof_path))?;
    let proof_json = serde_json::to_string(&embed_proof.proofs())
        .context("Failed to serialize proof to JSON")?;
    proof_file
        .write_all(proof_json.as_bytes())
        .context("Failed to write proof JSON to file")?;

    Ok(())
}

create_sdk_prove_client!(
    BabyBearProveClient,
    BabyBearPoseidon2,
    BabyBearBn254Poseidon2,
    BabyBearBn254,
    BabyBear
);
create_sdk_prove_client!(
    KoalaBearProveClient,
    KoalaBearPoseidon2,
    KoalaBearBn254Poseidon2,
    KoalaBearBn254,
    KoalaBear
);
