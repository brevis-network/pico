use itertools::Itertools;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use p3_matrix::dense::DenseStorage;
use pico_vm::{
    compiler::{
        recursion_v2::circuit::witness::Witnessable,
        riscv::compiler::{Compiler, SourceType},
    },
    configs::config::{Challenge, Val},
    emulator::{context::EmulatorContext, opts::EmulatorOpts, riscv::stdin::EmulatorStdin},
    instances::{
        chiptype::{recursion_chiptype_v2::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler_v2::{
            recursion_circuit::{
                combine::builder::RecursionCombineVerifierCircuit,
                compress::builder::RecursionCompressVerifierCircuit,
                embed::builder::RecursionEmbedVerifierCircuit, stdin::RecursionStdin,
            },
            riscv_circuit::{
                challenger::RiscvRecursionChallengers,
                compress::builder::RiscvCompressVerifierCircuit, stdin::RiscvRecursionStdin,
            },
        },
        configs::{
            embed_config::StarkConfig as EmbedSC,
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvBbSC,
        },
        machine::{
            recursion_combine::RecursionCombineMachine,
            recursion_compress::RecursionCompressMachine, recursion_embed::RecursionEmbedMachine,
            riscv_machine::RiscvMachine, riscv_recursion::RiscvRecursionMachine,
        },
    },
    machine::{
        logger::setup_logger, machine::MachineBehavior, proof::MetaProof, witness::ProvingWitness,
    },
    primitives::{
        consts::{
            BABYBEAR_S_BOX_DEGREE, COMBINE_DEGREE, COMBINE_SIZE, COMPRESS_DEGREE, DIGEST_SIZE,
            EMBED_DEGREE, PERMUTATION_WIDTH, RISCV_COMPRESS_DEGREE, RISCV_NUM_PVS,
        },
        consts_v2::RECURSION_NUM_PVS_V2,
    },
    recursion_v2::runtime::Runtime,
};
use std::{sync::Arc, time::Instant};
use tracing::info;

#[path = "common/parse_args.rs"]
mod parse_args;

fn main() {
    setup_logger();

    // -------- Riscv Machine --------

    info!("\n Begin RiscV..");

    let (elf, riscv_stdin, step, _field) = parse_args::parse_args();
    let start = Instant::now();

    info!("Creating RiscV Program..");
    let riscv_compiler = Compiler::new(SourceType::RiscV, elf);
    let riscv_program = riscv_compiler.compile();
    let riscv_config = RiscvBbSC::new();
    let riscv_chips = RiscvChipType::<BabyBear>::all_chips();

    // Setup config and chips.
    info!("Creating RiscVMachine (at {:?})..", start.elapsed());

    let riscv_machine = RiscvMachine::new(riscv_config, riscv_chips, RISCV_NUM_PVS);

    // Setup machine prover, verifier, pk and vk.
    info!("Setup RiscV machine (at {:?})..", start.elapsed());
    let (riscv_pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program.clone());

    info!("Construct RiscV proving witness..");
    let riscv_witness = ProvingWitness::setup_for_riscv(
        riscv_program,
        &riscv_stdin,
        EmulatorOpts::default(),
        EmulatorContext::default(),
    );

    // Generate the proof.
    info!("Generating RiscV proof (at {:?})..", start.elapsed());
    let riscv_proof = riscv_machine.prove(&riscv_pk, &riscv_witness);

    // Verify the proof.
    info!("Verifying RiscV proof (at {:?})..", start.elapsed());
    let riscv_result = riscv_machine.verify(&riscv_vk, &riscv_proof);
    info!(
        "The proof is verified: {} (at {:?})..",
        riscv_result.is_ok(),
        start.elapsed()
    );
    assert!(riscv_result.is_ok());
    if step == "riscv" {
        return;
    }

    // -------- Riscv Compression Recursion Machine --------

    let (riscv_compress_machine, riscv_compress_pks_vks_proofs) = {
        info!("\n Begin Riscv Compression Recursion");

        // TODO: Initialize the VK root.
        let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

        info!("\n Initializing RiscV compression machine");
        let machine = RiscvRecursionMachine::new(
            RecursionSC::new(),
            RecursionChipType::<BabyBear, RISCV_COMPRESS_DEGREE>::all_chips(),
            RECURSION_NUM_PVS_V2,
        );

        info!("\n Generating RiscV compression base and reconstruct challenger");
        let challengers = RiscvRecursionChallengers::new(
            riscv_machine.base_machine(),
            &riscv_vk,
            riscv_proof.proofs(),
        );

        let total = riscv_proof.proofs.len();
        info!("\n Generating RiscV compression PKs, VKs and proofs: total = {total}");
        // TODO: Consider to run in parallel.
        let pks_vks_proofs = riscv_proof.proofs.into_iter().enumerate().map(|(i, p)| {
            let flag_complete = i == total - 1;
            let flag_first_chunk = i == 0;
            info!(
                "\n Start generating RiscV compression proof-{i}: flag_complete = {flag_complete}, flag_first_chunk = {flag_first_chunk}",
            );
            let stdin = RiscvRecursionStdin::new(
                riscv_machine.base_machine(),
                &riscv_vk,
                p.clone(),
                challengers.clone(),
                flag_complete,
                flag_first_chunk,
                vk_root,
            );

            info!("\n Building RiscV compression program for proof-{i}");
            let program = RiscvCompressVerifierCircuit::<RecursionFC, RiscvBbSC>::build(
                riscv_machine.base_machine(),
                &stdin,
            );

            info!("\n Generating RiscV compression PK and VK for proof-{i}");
            let (pk, vk) = machine.setup_keys(&program);

            info!("\n Generating RiscV compression witness for proof-{i}");
            let stdin = EmulatorStdin::setup_for_riscv_compress(stdin);
            let witness = ProvingWitness::setup_for_riscv_recursion(
                program.into(),
                &stdin,
                machine.config(),
                EmulatorOpts::default(),
            );

            info!("\n Proving RiscV compression proof-{i}");
            let proof = machine.prove(&pk, &witness);

            info!("\n Verifying RiscV compression proof-{i}");
            machine.verify(&vk, &proof).expect("Failed to verify RiscV compression proof");

            info!("\n Finish generating RiscV compression proof-{i}");
            (pk, vk, proof)
        }).collect::<Vec<_>>();

        (machine, pks_vks_proofs)
    };

    // -------- Combine Recursion Machine --------

    let (recursion_combine_machine, recursion_combine_vks_and_proofs) = {
        info!("\n Begin Recursion Combine");

        // TODO: Initialize the VK root.
        let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

        info!("\n Initializing recursion combine machine");
        let machine = RecursionCombineMachine::new(
            RecursionSC::new(),
            RecursionChipType::<BabyBear, COMBINE_DEGREE>::all_chips(),
            RECURSION_NUM_PVS_V2,
        );

        let mut flag_complete = false;
        let mut layer_index = 1;
        let mut all_vks_and_proofs = riscv_compress_pks_vks_proofs
            .into_iter()
            .map(|(_pk, vk, mut proof)| {
                assert_eq!(
                    proof.proofs.len(),
                    1,
                    "RiscV compress proof must have one base proof"
                );
                let proof = proof.proofs.to_vec().pop().unwrap();
                (vk, proof)
            })
            .collect_vec();
        loop {
            all_vks_and_proofs = all_vks_and_proofs
                .chunks(COMBINE_SIZE)
                .enumerate()
                .map(|(i, vks_and_proofs)| {
                    let chunk_index = i + 1;
                    info!("\n Generating recursion combine VKs and proofs: layer-{layer_index} chunk-{chunk_index}");
                    let stdin = RecursionStdin::new(
                        machine.base_machine(),
                        vks_and_proofs.to_vec(),
                        flag_complete,
                        vk_root,
                    );

                    info!("\n Building recursion combine program: layer-{layer_index} chunk-{chunk_index}");
                    let program =
                        RecursionCombineVerifierCircuit::<RecursionFC, RecursionSC>::build(
                            machine.base_machine(),
                            &stdin,
                        );

                    info!("\n Generating recursion combine PK and VK: layer-{layer_index} chunk-{chunk_index}");
                    let (pk, vk) = machine.setup_keys(&program);

                    info!("\n Generating recursion combine witness: layer-{layer_index} chunk-{chunk_index}");
                    let stdin = EmulatorStdin::setup_for_combine(stdin);
                    let witness = ProvingWitness::setup_for_recursion(
                        program.into(),
                        &stdin,
                        machine.config(),
                        &vk,
                        EmulatorOpts::default(),
                    );

                    info!("\n Proving recursion combine proof: layer-{layer_index} chunk-{chunk_index}");
                    let mut proof = machine.prove(&pk, &witness);
                    assert_eq!(proof.proofs.len(), 1, "Must have one proof for each combine chunk");

                    (vk, proof.proofs.to_vec().pop().unwrap())
                })
                .collect_vec();

            if flag_complete {
                break;
            }
            flag_complete = all_vks_and_proofs.len() <= COMBINE_SIZE;
            layer_index += 1;
        }

        info!("\n Verifying recusion combine proofs");
        assert_eq!(all_vks_and_proofs.len(), 1, "Must have one proof combine");
        all_vks_and_proofs.iter().for_each(|(vk, proof)| {
            machine
                .verify(&vk, &MetaProof::new(Arc::from(vec![proof.clone()])))
                .expect("Failed to verify recursion combine proof");
        });

        (machine, all_vks_and_proofs)
    };

    // -------- Compress Recursion Machine --------

    let (recursion_compress_machine, recursion_compress_vk_and_proof) = {
        info!("\n Begin Recursion Compress");

        // TODO: Initialize the VK root.
        let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

        info!("\n Initializing recursion compress machine");
        let machine = RecursionCompressMachine::new(
            RecursionSC::compress(),
            RecursionChipType::<BabyBear, COMPRESS_DEGREE>::compress_chips(),
            RECURSION_NUM_PVS_V2,
        );

        info!("\n Generating recursion compress VKs and proofs");
        let stdin = RecursionStdin::new(
            machine.base_machine(),
            recursion_combine_vks_and_proofs.to_vec(),
            true,
            vk_root,
        );

        info!("\n Building recursion compress program");
        let program = RecursionCompressVerifierCircuit::<RecursionFC, RecursionSC>::build(
            recursion_combine_machine.base_machine(),
            &stdin,
        );

        info!("\n Generating recursion compress PK and VK");
        let (pk, vk) = machine.setup_keys(&program);

        let record = {
            let mut witness_stream = Vec::new();
            Witnessable::<RecursionFC>::write(&stdin, &mut witness_stream);
            let mut runtime = Runtime::<
                Val<RecursionSC>,
                Challenge<RecursionSC>,
                _,
                _,
                PERMUTATION_WIDTH,
                BABYBEAR_S_BOX_DEGREE,
            >::new(Arc::new(program), machine.config().perm.clone());
            runtime.witness_stream = witness_stream.into();
            runtime.run().unwrap();
            runtime.record
        };
        let witness = ProvingWitness::setup_with_records(vec![record]);

        info!("\n Proving recursion compress proof");
        let mut proof = machine.prove(&pk, &witness);

        info!("\n Verifying recursion compress proof");
        machine
            .verify(&vk, &proof)
            .expect("Failed to verify recursion compress proof");

        assert_eq!(proof.proofs().len(), 1);
        let proof = proof.proofs.to_vec().pop().unwrap();

        (machine, (vk, proof))
    };

    // -------- Embed Recursion Machine --------

    let (recursion_embed_machine, recursion_embed_vk_and_proof) = {
        info!("\n Begin Recursion Embed");

        // TODO: Initialize the VK root.
        let vk_root = [BabyBear::ZERO; DIGEST_SIZE];

        info!("\n Initializing recursion embed machine");
        let machine = RecursionEmbedMachine::<_, _, Vec<u8>>::new(
            EmbedSC::new(),
            RecursionChipType::<BabyBear, EMBED_DEGREE>::embed_chips(),
            RECURSION_NUM_PVS_V2,
        );

        info!("\n Generating recursion embed VKs and proofs");
        let stdin = RecursionStdin::new(
            recursion_compress_machine.base_machine(),
            vec![recursion_compress_vk_and_proof],
            true,
            vk_root,
        );

        info!("\n Building recursion embed program");
        let program = RecursionEmbedVerifierCircuit::<RecursionFC, RecursionSC>::build(
            recursion_compress_machine.base_machine(),
            &stdin,
        );

        info!("\n Generating recursion embed PK and VK");
        let (pk, vk) = machine.setup_keys(&program);

        let record = {
            let mut witness_stream = Vec::new();
            Witnessable::<RecursionFC>::write(&stdin, &mut witness_stream);
            let mut runtime = Runtime::<
                Val<RecursionSC>,
                Challenge<RecursionSC>,
                _,
                _,
                PERMUTATION_WIDTH,
                BABYBEAR_S_BOX_DEGREE,
            >::new(
                Arc::new(program),
                recursion_compress_machine.config().perm.clone(),
            );
            runtime.witness_stream = witness_stream.into();
            runtime.run().unwrap();
            runtime.record
        };
        let witness = ProvingWitness::setup_with_records(vec![record]);

        info!("\n Proving recursion embed proof");
        let mut proof = machine.prove(&pk, &witness);

        info!("\n Verifying recursion embed proof");
        machine
            .verify(&vk, &proof)
            .expect("Failed to verify recursion embed proof");

        assert_eq!(proof.proofs().len(), 1);
        let proof = proof.proofs.to_vec().pop().unwrap();

        (machine, (vk, proof))
    };
}
