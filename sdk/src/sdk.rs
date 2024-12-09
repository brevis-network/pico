use p3_baby_bear::BabyBear;
use p3_challenger::DuplexChallenger;
use pico_vm::{
    compiler::{
        recursion::{program::RecursionProgram, program_builder::hints::hintable::Hintable},
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::{
        config::{Challenge, StarkGenericConfig, Val},
        stark_config::{bb_bn254_poseidon2::BbBn254Poseidon2, bb_poseidon2::BabyBearPoseidon2},
    },
    emulator::{
        context::EmulatorContext,
        opts::EmulatorOpts,
        riscv::{riscv_emulator::RiscvEmulator, stdin::EmulatorStdin},
    },
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::{
            recursion_circuit::{
                combine::builder::RecursionCombineVerifierCircuit,
                compress::builder::RecursionCompressVerifierCircuit,
                embed::builder::RecursionEmbedVerifierCircuit, stdin::RecursionStdin,
            },
            riscv_circuit::compress::builder::RiscvCompressVerifierCircuit,
        },
        configs::riscv_config::StarkConfig,
        machine::{
            recursion_combine::RecursionCombineMachine,
            recursion_compress::RecursionCompressMachine, recursion_embed::RecursionEmbedMachine,
            riscv_machine::RiscvMachine, riscv_recursion::RiscvRecursionMachine,
        },
    },
    machine::{
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::MachineBehavior,
        utils::assert_vk_digest,
        witness::ProvingWitness,
    },
};

use pico_vm::{
    instances::configs::{
        embed_config::StarkConfig as EmbedSC,
        recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
        riscv_config::StarkConfig as RiscvSC,
    },
    machine::proof::MetaProof,
    primitives::consts::{
        BABYBEAR_S_BOX_DEGREE, COMBINE_DEGREE, COMBINE_SIZE, COMPRESS_DEGREE, EMBED_DEGREE,
        PERMUTATION_WIDTH, RECURSION_NUM_PVS, RISCV_COMPRESS_DEGREE, RISCV_NUM_PVS,
    },
    recursion::runtime::Runtime,
};

type CombineMachine =
    RecursionCombineMachine<BabyBearPoseidon2, RecursionChipType<BabyBear, COMBINE_DEGREE>>;

type RiscvCompressMachine =
    RiscvRecursionMachine<BabyBearPoseidon2, RecursionChipType<BabyBear, RISCV_COMPRESS_DEGREE>>;

type CompressMachine =
    RecursionCompressMachine<BabyBearPoseidon2, RecursionChipType<BabyBear, COMPRESS_DEGREE>>;

type EmbedMachine =
    RecursionEmbedMachine<BbBn254Poseidon2, RecursionChipType<BabyBear, EMBED_DEGREE>, Vec<u8>>;

struct ProvingKeys<SC: StarkGenericConfig> {
    pk: BaseProvingKey<SC>,
    vk: BaseVerifyingKey<SC>,
}

pub struct SDKProverClient {
    stdin: EmulatorStdin<Vec<u8>>,

    riscv_program: Program,
    riscv_machine: RiscvMachine<BabyBearPoseidon2, RiscvChipType<BabyBear>>,

    riscv_compress_program: RecursionProgram<BabyBear>,
    riscv_compress_machine: RiscvCompressMachine,

    combine_program: RecursionProgram<BabyBear>,
    combine_machine: CombineMachine,

    compress_program: RecursionProgram<BabyBear>,
    compress_machine: CompressMachine,

    embed_program: RecursionProgram<BabyBear>,
    embed_machine: EmbedMachine,
}

impl SDKProverClient {
    pub fn new(elf: Vec<u8>, stdin: EmulatorStdin<Vec<u8>>) -> SDKProverClient {
        let riscv_machine =
            RiscvMachine::new(RiscvSC::new(), RiscvChipType::all_chips(), RISCV_NUM_PVS);

        let riscv_compiler = Compiler::new(SourceType::RiscV, elf.as_slice());
        let riscv_program = riscv_compiler.compile();

        let riscv_compress_program = RiscvCompressVerifierCircuit::<RecursionFC, RiscvSC>::build(
            riscv_machine.base_machine(),
        );
        let riscv_compress_machine = RiscvRecursionMachine::new(
            RecursionSC::new(),
            RecursionChipType::<BabyBear, RISCV_COMPRESS_DEGREE>::all_chips(),
            RECURSION_NUM_PVS,
        );

        let combine_program = RecursionCombineVerifierCircuit::<RecursionFC, RecursionSC>::build(
            riscv_compress_machine.base_machine(),
        );
        let combine_machine = RecursionCombineMachine::new(
            RecursionSC::new(),
            RecursionChipType::<BabyBear, COMBINE_DEGREE>::all_chips(),
            RECURSION_NUM_PVS,
        );

        let compress_program = RecursionCompressVerifierCircuit::<RecursionFC, RecursionSC>::build(
            combine_machine.base_machine(),
        );
        let compress_machine = RecursionCompressMachine::new(
            RecursionSC::compress(),
            RecursionChipType::<BabyBear, COMPRESS_DEGREE>::compress_chips(),
            RECURSION_NUM_PVS,
        );

        let embed_program = RecursionEmbedVerifierCircuit::<RecursionFC, RecursionSC>::build(
            compress_machine.base_machine(),
        );
        let embed_machine = RecursionEmbedMachine::new(
            EmbedSC::new(),
            RecursionChipType::<BabyBear, EMBED_DEGREE>::embed_chips(),
            RECURSION_NUM_PVS,
        );

        Self {
            stdin,
            riscv_program,
            riscv_machine,
            riscv_compress_machine,
            riscv_compress_program,
            combine_program,
            combine_machine,
            compress_program,
            compress_machine,
            embed_program,
            embed_machine,
        }
    }

    fn setup(&self) -> ProvingKeys<RiscvSC> {
        if self.riscv_program.instructions.is_empty() {
            panic!("program is empty")
        }
        let (riscv_pk, riscv_vk) = self.riscv_machine.setup_keys(&self.riscv_program.clone());
        ProvingKeys {
            pk: riscv_pk,
            vk: riscv_vk,
        }
    }

    // todo: miss return value
    pub fn prove(&self) {
        let riscv_keys = &self.setup();
        let riscv_witness = ProvingWitness::setup_for_riscv(
            self.riscv_program.clone(),
            &self.stdin,
            EmulatorOpts::default(),
            EmulatorContext::default(),
        );
        let riscv_proof = self.riscv_machine.prove(&riscv_keys.pk, &riscv_witness);

        // Verify the proof.
        let riscv_result = self.riscv_machine.verify(&riscv_keys.vk, &riscv_proof);
        assert!(riscv_result.is_ok());

        // -------- Riscv Compression Recursion Machine --------
        let (riscv_compress_proof, riscv_compress_keys) =
            self.riscv_compress(&riscv_keys.vk, riscv_proof);
        let riscv_compress_result = self
            .riscv_compress_machine
            .verify(&riscv_compress_keys.vk, &riscv_compress_proof);
        assert!(riscv_compress_result.is_ok());

        // -------- Combine Recursion Machine --------
        let (combine_proof, combine_keys) =
            self.combine(riscv_compress_keys.vk, riscv_compress_proof);
        let combine_result = self
            .combine_machine
            .verify(&combine_keys.vk, &combine_proof);
        assert!(combine_result.is_ok());
        assert_vk_digest::<BabyBearPoseidon2>(&combine_proof, &riscv_keys.vk);

        // -------- Compress Recursion Machine --------
        let (compress_proof, compress_keys) = self.compress(combine_keys.vk, combine_proof);
        let compress_result = self
            .compress_machine
            .verify(&compress_keys.vk, &compress_proof);
        assert!(compress_result.is_ok());
        assert_vk_digest::<BabyBearPoseidon2>(&compress_proof, &riscv_keys.vk);

        // -------- Embed Recursion Machine --------
        let (embed_proof, embed_vk) = self.embed(compress_keys.vk, compress_proof);
        let embed_result = self.embed_machine.verify(&embed_vk, &embed_proof);
        assert!(embed_result.is_ok());
        assert_vk_digest::<BbBn254Poseidon2>(&embed_proof, &riscv_keys.vk);
    }

    pub fn dry_run(&self) {
        let mut emulator =
            RiscvEmulator::new(self.riscv_program.clone(), EmulatorOpts::test_opts());
        for input in &self.stdin.buffer {
            emulator.state.input_stream.push(input.clone());
        }
        emulator.run_fast().expect("dry run program failed");
    }

    fn combine(
        &self,
        compress_vk: BaseVerifyingKey<StarkConfig>,
        compress_proof: MetaProof<StarkConfig>,
    ) -> (MetaProof<StarkConfig>, ProvingKeys<RiscvSC>) {
        let (combine_pk, combine_vk) = self.combine_machine.setup_keys(&self.combine_program);
        let combine_stdin = EmulatorStdin::setup_for_combine(
            &compress_vk,
            self.riscv_compress_machine.base_machine(),
            compress_proof.proofs(),
            COMBINE_SIZE,
            false,
        );

        let combine_witness = ProvingWitness::setup_for_recursion(
            self.combine_program.clone(),
            &combine_stdin,
            self.combine_machine.config(),
            &combine_vk,
            EmulatorOpts::default(),
        );

        let combine_proof = self.combine_machine.prove(&combine_pk, &combine_witness);

        (
            combine_proof,
            ProvingKeys {
                pk: combine_pk,
                vk: combine_vk,
            },
        )
    }

    fn riscv_compress(
        &self,
        riscv_vk: &BaseVerifyingKey<StarkConfig>,
        riscv_proof: MetaProof<StarkConfig>,
    ) -> (MetaProof<StarkConfig>, ProvingKeys<RiscvSC>) {
        let (compress_pk, compress_vk) = self
            .riscv_compress_machine
            .setup_keys(&self.riscv_compress_program);
        let mut riscv_challenger = DuplexChallenger::new(self.riscv_machine.config().perm.clone());
        let riscv_compress_stdin = EmulatorStdin::setup_for_riscv_compress(
            riscv_vk,
            self.riscv_machine.base_machine(),
            riscv_proof.proofs(),
            &mut riscv_challenger,
        );

        let riscv_compress_witness = ProvingWitness::setup_for_riscv_recursion(
            self.riscv_compress_program.clone(),
            &riscv_compress_stdin,
            self.riscv_compress_machine.config(),
            EmulatorOpts::default(),
        );

        // Generate the proof.
        let riscv_compress_proof = self
            .riscv_compress_machine
            .prove(&compress_pk, &riscv_compress_witness);

        (
            riscv_compress_proof,
            ProvingKeys {
                pk: compress_pk,
                vk: compress_vk,
            },
        )
    }

    fn compress(
        &self,
        combine_vk: BaseVerifyingKey<StarkConfig>,
        combine_proof: MetaProof<StarkConfig>,
    ) -> (MetaProof<StarkConfig>, ProvingKeys<RiscvSC>) {
        let (compress_pk, compress_vk) = self.compress_machine.setup_keys(&self.compress_program);

        let compress_record = {
            let stdin = RecursionStdin {
                vk: &combine_vk,
                machine: self.combine_machine.base_machine(),
                proofs: combine_proof.proofs().to_vec(),
                flag_complete: true,
            };

            let mut witness_stream = Vec::new();
            witness_stream.extend(stdin.write());

            let mut runtime = Runtime::<
                Val<RecursionSC>,
                Challenge<RecursionSC>,
                _,
                _,
                PERMUTATION_WIDTH,
                BABYBEAR_S_BOX_DEGREE,
            >::new(
                &self.compress_program,
                self.compress_machine.config().perm.clone(),
            );
            runtime.witness_stream = witness_stream.into();
            runtime.run().unwrap();
            runtime.print_stats();
            runtime.record
        };
        let compress_witness = ProvingWitness::setup_with_records(vec![compress_record]);
        let compress_proof = self.compress_machine.prove(&compress_pk, &compress_witness);

        (
            compress_proof,
            ProvingKeys {
                pk: compress_pk,
                vk: compress_vk,
            },
        )
    }

    fn embed(
        &self,
        compress_vk: BaseVerifyingKey<StarkConfig>,
        compress_proof: MetaProof<StarkConfig>,
    ) -> (MetaProof<EmbedSC>, BaseVerifyingKey<EmbedSC>) {
        let (embed_pk, embed_vk) = self.embed_machine.setup_keys(&self.embed_program);

        let embed_record = {
            let stdin = RecursionStdin {
                vk: &compress_vk,
                machine: self.compress_machine.base_machine(),
                proofs: compress_proof.proofs().to_vec(),
                flag_complete: true,
            };

            let mut witness_stream = Vec::new();
            witness_stream.extend(stdin.write());

            let mut runtime = Runtime::<
                Val<RecursionSC>,
                Challenge<RecursionSC>,
                _,
                _,
                PERMUTATION_WIDTH,
                BABYBEAR_S_BOX_DEGREE,
            >::new(
                &self.embed_program,
                self.compress_machine.config().perm.clone(),
            );
            runtime.witness_stream = witness_stream.into();
            runtime.run().unwrap();
            runtime.print_stats();

            runtime.record
        };

        let embed_witness: ProvingWitness<
            '_,
            EmbedSC,
            RecursionChipType<BabyBear, EMBED_DEGREE>,
            Vec<u8>,
        > = ProvingWitness::setup_with_records(vec![embed_record]);

        let embed_proof = self.embed_machine.prove(&embed_pk, &embed_witness);

        (embed_proof, embed_vk)
    }
}
