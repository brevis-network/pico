use hashbrown::HashSet;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use pico_vm::{
    compiler::recursion_v2::circuit::stark::dummy_challenger,
    configs::config::StarkGenericConfig,
    instances::{
        chiptype::{recursion_chiptype_v2::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler_v2::{
            riscv_circuit::{
                convert::builder::ConvertVerifierCircuit,
                stdin::{dummy_vk_and_chunk_proof, ConvertStdin},
            },
            shapes::{
                compress_shape::{RecursionShapeConfig, RecursionVkShape},
                riscv_shape::RiscvShapeConfig,
                PicoRecursionProgramShape,
            },
            vk_merkle::{
                builder::{CombineVkVerifierCircuit, CompressVkVerifierCircuit},
                stdin::RecursionVkStdin,
            },
        },
        configs::{
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            riscv_config::StarkConfig as RiscvSC,
        },
        machine::{
            combine_vk::CombineVkMachine, compress_vk::CompressVkMachine, convert::ConvertMachine,
            riscv::RiscvMachine,
        },
    },
    machine::{keys::HashableKey, machine::MachineBehavior},
    primitives::consts::{
        BABYBEAR_NUM_EXTERNAL_ROUNDS, BABYBEAR_NUM_INTERNAL_ROUNDS, BABYBEAR_W, COMBINE_DEGREE,
        COMPRESS_DEGREE, CONVERT_DEGREE, DIGEST_SIZE, RECURSION_NUM_PVS, RISCV_NUM_PVS,
    },
};
use rayon::{iter::ParallelIterator, prelude::IntoParallelRefIterator};
use std::{
    collections::{BTreeMap, BTreeSet},
    fs::File,
};

pub fn vk_digest_from_shape(shape: PicoRecursionProgramShape) -> [BabyBear; DIGEST_SIZE] {
    // COMBINE_DEGREE == CONVERT_DEGREE == COMPRESS_DEGREE == 3
    let recursion_shape_config = RecursionShapeConfig::<
        BabyBear,
        RecursionChipType<
            BabyBear,
            COMBINE_DEGREE,
            BABYBEAR_W,
            BABYBEAR_NUM_EXTERNAL_ROUNDS,
            BABYBEAR_NUM_INTERNAL_ROUNDS,
            { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
        >,
    >::default();

    match shape {
        PicoRecursionProgramShape::Convert(shape) => {
            let chips = RiscvChipType::<
                BabyBear,
                { BABYBEAR_NUM_EXTERNAL_ROUNDS / 2 },
                BABYBEAR_NUM_INTERNAL_ROUNDS,
            >::all_chips();
            let riscv_machine = RiscvMachine::new(RiscvSC::new(), chips, RISCV_NUM_PVS);

            let base_machine = riscv_machine.base_machine();

            let (mut vks, chunk_proofs): (Vec<_>, Vec<_>) = shape
                .proof_shapes
                .iter()
                .map(|shape| dummy_vk_and_chunk_proof(base_machine, shape))
                .unzip();

            let vk = vks.pop().unwrap();
            let base_challenger = dummy_challenger(&base_machine.config());
            let reconstruct_challenger = dummy_challenger(&base_machine.config());

            let stdin = ConvertStdin {
                machine: base_machine.clone(),
                riscv_vk: vk,
                proofs: chunk_proofs.into(),
                base_challenger,
                reconstruct_challenger,
                flag_complete: shape.is_complete,
                vk_root: [BabyBear::ZERO; DIGEST_SIZE],
                flag_first_chunk: false,
            };

            let mut program = ConvertVerifierCircuit::<
                RecursionFC,
                RiscvSC,
                { BABYBEAR_NUM_EXTERNAL_ROUNDS / 2 },
                BABYBEAR_NUM_INTERNAL_ROUNDS,
            >::build(base_machine, &stdin);

            recursion_shape_config.padding_shape(&mut program);

            let machine = ConvertMachine::<
                _,
                _,
                { BABYBEAR_NUM_EXTERNAL_ROUNDS / 2 },
                BABYBEAR_NUM_INTERNAL_ROUNDS,
            >::new(
                RecursionSC::new(),
                RecursionChipType::<
                    BabyBear,
                    CONVERT_DEGREE,
                    BABYBEAR_W,
                    BABYBEAR_NUM_EXTERNAL_ROUNDS,
                    BABYBEAR_NUM_INTERNAL_ROUNDS,
                    { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
                >::all_chips(),
                RECURSION_NUM_PVS,
            );

            let (_pk, vk) = machine.setup_keys(&program);
            vk.hash_field()
        }
        PicoRecursionProgramShape::Combine(shape) => {
            let machine = CombineVkMachine::<
                _,
                _,
                { BABYBEAR_NUM_EXTERNAL_ROUNDS / 2 },
                BABYBEAR_NUM_INTERNAL_ROUNDS,
            >::new(
                RecursionSC::new(),
                RecursionChipType::<
                    BabyBear,
                    COMBINE_DEGREE,
                    BABYBEAR_W,
                    BABYBEAR_NUM_EXTERNAL_ROUNDS,
                    BABYBEAR_NUM_INTERNAL_ROUNDS,
                    { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
                >::all_chips(),
                RECURSION_NUM_PVS,
            );

            // let recursion_machine = RiscvRecursionMachine::new(
            //     RecursionSC::new(),
            //     RecursionChipType::<BabyBear, RISCV_COMPRESS_DEGREE>::all_chips(),
            //     RECURSION_NUM_PVS,
            // );
            // println!("combine shape: {:?}", shape);
            let base_machine = machine.base_machine();
            let stdin_with_vk = RecursionVkStdin::dummy(base_machine, &shape);
            let mut program_with_vk = CombineVkVerifierCircuit::<
                RecursionFC,
                RecursionSC,
                RecursionChipType<
                    BabyBear,
                    COMBINE_DEGREE,
                    BABYBEAR_W,
                    BABYBEAR_NUM_EXTERNAL_ROUNDS,
                    BABYBEAR_NUM_INTERNAL_ROUNDS,
                    { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
                >,
            >::build(base_machine, &stdin_with_vk);

            recursion_shape_config.padding_shape(&mut program_with_vk);

            let (_pk, vk) = machine.setup_keys(&program_with_vk);
            vk.hash_field()
        }
        PicoRecursionProgramShape::Compress(shape) => {
            // TODO: all_chips ?
            let combine_machine = CombineVkMachine::<
                _,
                _,
                { BABYBEAR_NUM_EXTERNAL_ROUNDS / 2 },
                BABYBEAR_NUM_INTERNAL_ROUNDS,
            >::new(
                RecursionSC::new(),
                RecursionChipType::<
                    BabyBear,
                    COMBINE_DEGREE,
                    BABYBEAR_W,
                    BABYBEAR_NUM_EXTERNAL_ROUNDS,
                    BABYBEAR_NUM_INTERNAL_ROUNDS,
                    { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
                >::all_chips(),
                RECURSION_NUM_PVS,
            );
            let machine = CompressVkMachine::new(
                RecursionSC::compress(),
                RecursionChipType::<
                    BabyBear,
                    COMPRESS_DEGREE,
                    BABYBEAR_W,
                    BABYBEAR_NUM_EXTERNAL_ROUNDS,
                    BABYBEAR_NUM_INTERNAL_ROUNDS,
                    { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
                >::compress_chips(),
                RECURSION_NUM_PVS,
            );
            let combine_base_machine = combine_machine.base_machine();
            let stdin_with_vk = RecursionVkStdin::dummy(combine_base_machine, &shape);
            let mut program_with_vk = CompressVkVerifierCircuit::<
                RecursionFC,
                RecursionSC,
                BABYBEAR_W,
                BABYBEAR_NUM_EXTERNAL_ROUNDS,
                BABYBEAR_NUM_INTERNAL_ROUNDS,
                { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
            >::build(combine_base_machine, &stdin_with_vk);
            let compress_pad_shape = RecursionChipType::<
                BabyBear,
                COMPRESS_DEGREE,
                BABYBEAR_W,
                BABYBEAR_NUM_EXTERNAL_ROUNDS,
                BABYBEAR_NUM_INTERNAL_ROUNDS,
                { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
            >::compress_shape();
            program_with_vk.shape = Some(compress_pad_shape);
            let (_pk, vk) = machine.setup_keys(&program_with_vk);
            vk.hash_field()
        }
    }
}

fn load_vk_map(filename: &str) -> BTreeMap<[BabyBear; DIGEST_SIZE], usize> {
    if let Ok(mut file) = File::open(filename) {
        if let Ok(vk_map) =
            bincode::deserialize_from::<_, BTreeMap<[BabyBear; DIGEST_SIZE], usize>>(&mut file)
        {
            return vk_map;
        }
    }
    BTreeMap::new()
}

fn save_vk_map(
    filename: &str,
    vk_map: &BTreeMap<[BabyBear; DIGEST_SIZE], usize>,
) -> std::io::Result<()> {
    let mut file = File::create(filename)?;
    bincode::serialize_into(&mut file, vk_map)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

fn main() {
    // TODO: remove redundant count (merkle tree height set to 0 for dummy shape count)
    let start_time = std::time::Instant::now();
    let riscv_shape_config = RiscvShapeConfig::<
        BabyBear,
        { BABYBEAR_NUM_EXTERNAL_ROUNDS / 2 },
        BABYBEAR_NUM_INTERNAL_ROUNDS,
    >::default();
    // COMBINE_DEGREE == COMPRESS_DEGREE == 3
    let recursion_shape_config = RecursionShapeConfig::<
        BabyBear,
        RecursionChipType<
            BabyBear,
            COMBINE_DEGREE,
            BABYBEAR_W,
            BABYBEAR_NUM_EXTERNAL_ROUNDS,
            BABYBEAR_NUM_INTERNAL_ROUNDS,
            { BABYBEAR_NUM_INTERNAL_ROUNDS - 1 },
        >,
    >::default();

    let riscv_recursion_shapes = riscv_shape_config
        .generate_all_allowed_shapes()
        .map(|shape| PicoRecursionProgramShape::Convert(shape.into()));

    let combine_shapes_2 = recursion_shape_config
        .get_all_shape_combinations(2)
        .map(|shape| {
            PicoRecursionProgramShape::Combine(RecursionVkShape::from_proof_shapes(shape, 0))
        });

    let combine_shapes_1 = recursion_shape_config
        .get_all_shape_combinations(1)
        .map(|shape| {
            PicoRecursionProgramShape::Combine(RecursionVkShape::from_proof_shapes(shape, 0))
        });

    let compress_shape = recursion_shape_config
        .get_all_shape_combinations(1)
        .map(|shape| {
            PicoRecursionProgramShape::Compress(RecursionVkShape::from_proof_shapes(shape, 0))
        });

    let all_shapes: Vec<_> = riscv_recursion_shapes
        .chain(combine_shapes_2)
        .chain(combine_shapes_1)
        .chain(compress_shape)
        .collect();

    let all_shapes: Vec<_> = HashSet::<_>::from_iter(all_shapes).into_iter().collect();

    let total_num = all_shapes.len();
    println!(
        "Total num of all shapes (after deduplication): {}",
        total_num
    );

    let merkle_tree_height = total_num.next_power_of_two().ilog2() as usize;

    let riscv_recursion_shapes = riscv_shape_config
        .generate_all_allowed_shapes()
        .map(|shape| PicoRecursionProgramShape::Convert(shape.into()));

    let combine_shapes_2 = recursion_shape_config
        .get_all_shape_combinations(2)
        .map(|shape| {
            PicoRecursionProgramShape::Combine(RecursionVkShape::from_proof_shapes(
                shape,
                merkle_tree_height,
            ))
        });

    let combine_shapes_1 = recursion_shape_config
        .get_all_shape_combinations(1)
        .map(|shape| {
            PicoRecursionProgramShape::Combine(RecursionVkShape::from_proof_shapes(
                shape,
                merkle_tree_height,
            ))
        });

    let compress_shape = recursion_shape_config
        .get_all_shape_combinations(1)
        .map(|shape| {
            PicoRecursionProgramShape::Compress(RecursionVkShape::from_proof_shapes(
                shape,
                merkle_tree_height,
            ))
        });

    let all_shapes: Vec<_> = riscv_recursion_shapes
        .chain(combine_shapes_2)
        .chain(combine_shapes_1)
        .chain(compress_shape)
        .collect();

    let all_shapes: Vec<_> = HashSet::<_>::from_iter(all_shapes).into_iter().collect();

    let results: Vec<_> = all_shapes
        .par_iter()
        .map(|shape| {
            let vk_digest = vk_digest_from_shape(shape.clone());
            println!("vk_digest: {:?}", vk_digest);
            vk_digest
        })
        .collect();

    let vk_map = load_vk_map("vk_map.bin");
    let mut vk_set: BTreeSet<[BabyBear; DIGEST_SIZE]> = vk_map.keys().copied().collect();

    let new_vk_set: BTreeSet<_> = results.into_iter().collect();
    vk_set.extend(new_vk_set);

    let vk_map = vk_set
        .into_iter()
        .enumerate()
        .map(|(i, vk)| (vk, i))
        .collect::<BTreeMap<_, _>>();

    save_vk_map("vk_map.bin", &vk_map).expect("Failed to save updated vk_map.bin");

    println!("vk_map has been serialized and saved to vk_map.bin");
    let total_time = start_time.elapsed().as_secs_f32();
    println!("Total time for building vk map: {}", total_time);
}
