use super::VkRoot;
use crate::{
    gateway::handler::proof_tree::IndexedProof,
    messages::riscv::{RiscvRequest, RiscvResponse},
};
use log::debug;
use p3_field::{extension::BinomiallyExtendable, PrimeField32};
use p3_symmetric::Permutation;
use pico_perf::common::{
    bench_program::{load, BenchProgram},
    print_utils::log_section,
};
use pico_vm::{
    compiler::{
        recursion::circuit::hash::FieldHasher,
        riscv::{
            compiler::{Compiler, SourceType},
            program::Program,
        },
    },
    configs::{
        config::{FieldGenericConfig, StarkGenericConfig, Val},
        field_config::{BabyBearSimple, KoalaBearSimple},
        stark_config::{BabyBearPoseidon2, KoalaBearPoseidon2},
    },
    emulator::{opts::EmulatorOpts, stdin::EmulatorStdin},
    instances::{
        chiptype::{recursion_chiptype::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler::{
            shapes::{recursion_shape::RecursionShapeConfig, riscv_shape::RiscvShapeConfig},
            vk_merkle::HasStaticVkManager,
        },
        machine::{convert::ConvertMachine, riscv::RiscvMachine},
    },
    machine::{
        field::FieldSpecificPoseidon2Config,
        keys::{BaseProvingKey, BaseVerifyingKey},
        machine::MachineBehavior,
        witness::ProvingWitness,
    },
    primitives::{
        consts::{DIGEST_SIZE, EXTENSION_DEGREE, RECURSION_NUM_PVS, RISCV_NUM_PVS},
        Poseidon2Init,
    },
};
use std::{sync::Arc, time::Instant};
use tracing::info;

pub struct RiscvConvertProver<SC>
where
    SC: StarkGenericConfig,
    SC::Val: FieldSpecificPoseidon2Config + PrimeField32,
{
    prover_id: String,
    riscv_shape_config: Option<RiscvShapeConfig<SC::Val>>,
    recursion_shape_config: Option<RecursionShapeConfig<SC::Val, RecursionChipType<SC::Val>>>,
    riscv_machine: RiscvMachine<SC, RiscvChipType<SC::Val>>,
    convert_machine: ConvertMachine<SC, RecursionChipType<SC::Val>>,
    pk: BaseProvingKey<SC>,
    riscv_vk: BaseVerifyingKey<SC>,
}

impl<SC> RiscvConvertProver<SC>
where
    SC: StarkGenericConfig
        + HasStaticVkManager
        + FieldHasher<Val<SC>, Digest = [Val<SC>; DIGEST_SIZE]>
        + Default
        + Send
        + 'static,
    SC::Val: Ord
        + PrimeField32
        + Poseidon2Init
        + FieldSpecificPoseidon2Config
        + BinomiallyExtendable<EXTENSION_DEGREE>,
    <SC::Val as Poseidon2Init>::Poseidon2: Permutation<[SC::Val; 16]>,
{
    pub fn new(prover_id: String, program: BenchProgram) -> Self {
        // opts and setups
        let vk_manager = <SC as HasStaticVkManager>::static_vk_manager();
        let vk_enabled = vk_manager.vk_verification_enabled();
        let riscv_shape_config = if vk_enabled {
            Some(RiscvShapeConfig::<SC::Val>::default())
        } else {
            None
        };
        let recursion_shape_config = if vk_enabled {
            Some(RecursionShapeConfig::<SC::Val, RecursionChipType<SC::Val>>::default())
        } else {
            None
        };
        let (elf, _) = load::<Program>(&program).unwrap();

        let riscv_machine =
            RiscvMachine::new(SC::default(), RiscvChipType::all_chips(), RISCV_NUM_PVS);

        let riscv_compiler = Compiler::new(SourceType::RISCV, &elf);
        let mut riscv_program = riscv_compiler.compile();
        if let Some(ref shape_config) = riscv_shape_config {
            let program = Arc::get_mut(&mut riscv_program).expect("cannot get_mut arc");
            shape_config
                .padding_preprocessed_shape(program)
                .expect("cannot padding preprocessed shape");
        }
        let (pk, riscv_vk) = riscv_machine.setup_keys(&riscv_program);

        let convert_machine = ConvertMachine::new(
            SC::default(),
            RecursionChipType::<SC::Val>::all_chips(),
            RECURSION_NUM_PVS,
        );

        Self {
            prover_id,
            riscv_shape_config,
            recursion_shape_config,
            riscv_machine,
            convert_machine,
            pk,
            riscv_vk,
        }
    }
}

/// specialization for running prover on either babybear or koalabear
pub trait RiscvConvertHandler<SC: StarkGenericConfig> {
    fn process(&self, req: RiscvRequest, vk_root: &VkRoot<SC>) -> RiscvResponse<SC>;
}

impl<SC> RiscvConvertHandler<SC> for RiscvConvertProver<SC>
where
    SC: StarkGenericConfig,
    SC::Val: FieldSpecificPoseidon2Config + PrimeField32,
{
    /// default implementation
    default fn process(&self, _req: RiscvRequest, _vk_root: &VkRoot<SC>) -> RiscvResponse<SC> {
        panic!("unsupported");
    }
}

impl RiscvConvertHandler<BabyBearPoseidon2> for RiscvConvertProver<BabyBearPoseidon2> {
    fn process(
        &self,
        req: RiscvRequest,
        vk_root: &VkRoot<BabyBearPoseidon2>,
    ) -> RiscvResponse<BabyBearPoseidon2> {
        log_section("RISCV PHASE");

        let mut challenger = self.riscv_machine.config().challenger().clone();
        self.pk.observed_by(&mut challenger);

        let chunk_index = req.chunk_index;
        let is_last_chunk = req.record.is_last;

        info!(
            "[{}] receive riscv-convert request: chunk_index = {}",
            self.prover_id, chunk_index,
        );

        let start = Instant::now();

        let proof = self.riscv_machine.prove_record(
            chunk_index,
            &self.pk,
            &challenger,
            self.riscv_shape_config.as_ref(),
            req.record,
        );

        info!("RISCV Phase complete! chunk_index: {}", chunk_index);

        log_section("CONVERT PHASE");

        let recursion_opts = EmulatorOpts::default();
        debug!("recursion_opts: {:?}", recursion_opts);

        let convert_stdin = EmulatorStdin::setup_for_convert_with_index::<
            <BabyBearSimple as FieldGenericConfig>::F,
            BabyBearSimple,
        >(
            &self.riscv_vk,
            *vk_root,
            self.riscv_machine.base_machine(),
            &proof,
            &self.recursion_shape_config,
            chunk_index,
            is_last_chunk,
        );
        let convert_witness = ProvingWitness::setup_for_convert(
            convert_stdin,
            BabyBearPoseidon2::new().into(),
            recursion_opts,
        );
        let proof = self
            .convert_machine
            .prove_with_index(chunk_index as u32, &convert_witness);
        let proof = IndexedProof::new(proof, chunk_index, chunk_index);

        info!(
            "[{}] finish riscv proving chunk-{chunk_index}, time used: {}ms",
            self.prover_id,
            start.elapsed().as_millis(),
        );

        // return the riscv-convert result
        RiscvResponse { chunk_index, proof }
    }
}

impl RiscvConvertHandler<KoalaBearPoseidon2> for RiscvConvertProver<KoalaBearPoseidon2> {
    fn process(
        &self,
        req: RiscvRequest,
        vk_root: &VkRoot<KoalaBearPoseidon2>,
    ) -> RiscvResponse<KoalaBearPoseidon2> {
        log_section("RISCV PHASE");

        let mut challenger = self.riscv_machine.config().challenger().clone();
        self.pk.observed_by(&mut challenger);

        let chunk_index = req.chunk_index;
        let is_last_chunk = req.record.is_last;

        info!(
            "[{}] receive riscv-convert request: chunk_index = {}",
            self.prover_id, chunk_index,
        );

        let start = Instant::now();

        let proof = self.riscv_machine.prove_record(
            chunk_index,
            &self.pk,
            &challenger,
            self.riscv_shape_config.as_ref(),
            req.record,
        );

        info!("RISCV Phase complete! chunk_index: {}", chunk_index);

        log_section("CONVERT PHASE");

        let recursion_opts = EmulatorOpts::default();
        debug!("recursion_opts: {:?}", recursion_opts);

        let convert_stdin = EmulatorStdin::setup_for_convert_with_index::<
            <KoalaBearSimple as FieldGenericConfig>::F,
            KoalaBearSimple,
        >(
            &self.riscv_vk,
            *vk_root,
            self.riscv_machine.base_machine(),
            &proof,
            &self.recursion_shape_config,
            chunk_index,
            is_last_chunk,
        );
        let convert_witness = ProvingWitness::setup_for_convert(
            convert_stdin,
            KoalaBearPoseidon2::new().into(),
            recursion_opts,
        );

        let proof = self
            .convert_machine
            .prove_with_index(chunk_index as u32, &convert_witness);
        let proof = IndexedProof::new(proof, chunk_index, chunk_index);

        info!(
            "[worker] finish proving chunk-{chunk_index}, time used: {}ms",
            start.elapsed().as_millis()
        );

        // return the riscv-convert result
        RiscvResponse { chunk_index, proof }
    }
}
