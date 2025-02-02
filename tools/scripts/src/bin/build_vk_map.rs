use clap::{Parser, ValueEnum};
use hashbrown::HashSet;
use p3_baby_bear::BabyBear;
use p3_field::FieldAlgebra;
use p3_koala_bear::KoalaBear;
use pico_vm::{
    compiler::recursion_v2::circuit::stark::{dummy_challenger_bb, dummy_challenger_kb},
    configs::{
        config::StarkGenericConfig,
        stark_config::{bb_poseidon2::BabyBearPoseidon2, kb_poseidon2::KoalaBearPoseidon2},
    },
    instances::{
        chiptype::{recursion_chiptype_v2::RecursionChipType, riscv_chiptype::RiscvChipType},
        compiler_v2::{
            riscv_circuit::{
                convert::builder::ConvertVerifierCircuit,
                stdin::{dummy_vk_and_chunk_proof, dummy_vk_and_chunk_proof_kb, ConvertStdin},
            },
            shapes::{
                compress_shape::{RecursionShapeConfig, RecursionVkShape},
                riscv_shape::RiscvShapeConfig,
                PicoRecursionProgramShape, ProofShape,
            },
            vk_merkle::{
                builder::{CombineVkVerifierCircuit, CompressVkVerifierCircuit},
                stdin::RecursionVkStdin,
            },
        },
        configs::{
            recur_config::{FieldConfig as RecursionFC, StarkConfig as RecursionSC},
            recur_kb_config::{FieldConfig as RecursionKbFC, StarkConfig as RecursionKbSC},
            riscv_config::StarkConfig as RiscvSC,
            riscv_kb_config::StarkConfig as RiscvKbSC,
        },
        machine::{
            combine_vk::CombineVkMachine, compress_vk::CompressVkMachine, convert::ConvertMachine,
            riscv::RiscvMachine,
        },
    },
    machine::{keys::HashableKey, machine::MachineBehavior},
    primitives::consts::{
        COMBINE_DEGREE, COMPRESS_DEGREE, CONVERT_DEGREE, DIGEST_SIZE, RECURSION_NUM_PVS,
        RISCV_NUM_PVS,
    },
};
use rayon::{iter::ParallelIterator, prelude::IntoParallelRefIterator};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    fs::File,
    io,
    sync::{Arc, RwLock},
};

macro_rules! define_vk_digest_from_shape {
    ($func_name:ident, $F:ty, $RiscvSC:ty, $dummy_fn:expr, $dummy_challenger:expr, $RecursionFC:ty, $RecursionSC:ty, $poseidon_type:ty) => {
        pub fn $func_name(shape: PicoRecursionProgramShape) -> [$F; DIGEST_SIZE] {
            // COMBINE_DEGREE == CONVERT_DEGREE == COMPRESS_DEGREE == 3
            let recursion_shape_config =
                RecursionShapeConfig::<$F, RecursionChipType<$F, COMBINE_DEGREE>>::default();

            match shape {
                PicoRecursionProgramShape::Convert(shape) => {
                    let chips = RiscvChipType::<$F>::all_chips();
                    let riscv_machine = RiscvMachine::new(<$RiscvSC>::new(), chips, RISCV_NUM_PVS);

                    let base_machine = riscv_machine.base_machine();

                    let (mut vks, chunk_proofs): (Vec<_>, Vec<_>) = shape
                        .proof_shapes
                        .iter()
                        .map(|shape| $dummy_fn(base_machine, shape))
                        .unzip();

                    let vk = vks.pop().unwrap();
                    let base_challenger = $dummy_challenger(&base_machine.config());
                    let reconstruct_challenger = $dummy_challenger(&base_machine.config());

                    let stdin = ConvertStdin {
                        machine: base_machine.clone(),
                        riscv_vk: vk,
                        proofs: chunk_proofs.into(),
                        base_challenger,
                        reconstruct_challenger,
                        flag_complete: shape.is_complete,
                        vk_root: [<$F>::ZERO; DIGEST_SIZE],
                        flag_first_chunk: false,
                    };

                    let mut program = ConvertVerifierCircuit::<$RecursionFC, $RiscvSC>::build(
                        base_machine,
                        &stdin,
                    );

                    recursion_shape_config.padding_shape(&mut program);

                    let machine = ConvertMachine::new(
                        <$RecursionSC>::new(),
                        RecursionChipType::<$F, CONVERT_DEGREE>::convert_chips(),
                        RECURSION_NUM_PVS,
                    );

                    let (_pk, vk) = machine.setup_keys(&program);
                    vk.hash_field()
                }
                PicoRecursionProgramShape::Combine(shape) => {
                    let machine = CombineVkMachine::new(
                        <$RecursionSC>::new(),
                        RecursionChipType::<$F, COMBINE_DEGREE>::combine_chips(),
                        RECURSION_NUM_PVS,
                    );

                    // let recursion_machine = RiscvRecursionMachine::new(
                    //     RecursionSC::new(),
                    //     RecursionChipType::<$F, RISCV_COMPRESS_DEGREE>::all_chips(),
                    //     RECURSION_NUM_PVS,
                    // );
                    // println!("combine shape: {:?}", shape);
                    let base_machine = machine.base_machine();
                    let stdin_with_vk = RecursionVkStdin::<
                        $poseidon_type,
                        RecursionChipType<$F, COMBINE_DEGREE>,
                    >::dummy(base_machine, &shape);
                    let mut program_with_vk = CombineVkVerifierCircuit::<
                        $RecursionFC,
                        $RecursionSC,
                        RecursionChipType<$F, COMBINE_DEGREE>,
                    >::build(base_machine, &stdin_with_vk);

                    recursion_shape_config.padding_shape(&mut program_with_vk);

                    let (_pk, vk) = machine.setup_keys(&program_with_vk);
                    vk.hash_field()
                }
                PicoRecursionProgramShape::Compress(shape) => {
                    let combine_machine = CombineVkMachine::new(
                        <$RecursionSC>::new(),
                        RecursionChipType::<$F, COMBINE_DEGREE>::combine_chips(),
                        RECURSION_NUM_PVS,
                    );
                    let machine = CompressVkMachine::new(
                        <$RecursionSC>::compress(),
                        RecursionChipType::<$F, COMPRESS_DEGREE>::compress_chips(),
                        RECURSION_NUM_PVS,
                    );
                    let combine_base_machine = combine_machine.base_machine();
                    let stdin_with_vk = RecursionVkStdin::<
                        $poseidon_type,
                        RecursionChipType<$F, COMBINE_DEGREE>,
                    >::dummy(combine_base_machine, &shape);
                    let mut program_with_vk =
                        CompressVkVerifierCircuit::<$RecursionFC, $RecursionSC>::build(
                            combine_base_machine,
                            &stdin_with_vk,
                        );
                    let compress_pad_shape =
                        RecursionChipType::<$F, COMPRESS_DEGREE>::compress_shape();
                    program_with_vk.shape = Some(compress_pad_shape);
                    let (_pk, vk) = machine.setup_keys(&program_with_vk);
                    vk.hash_field()
                }
            }
        }
    };
}

define_vk_digest_from_shape!(
    vk_digest_from_shape,
    BabyBear,
    RiscvSC,
    dummy_vk_and_chunk_proof,
    dummy_challenger_bb,
    RecursionFC,
    RecursionSC,
    BabyBearPoseidon2
);
define_vk_digest_from_shape!(
    vk_digest_from_shape_kb,
    KoalaBear,
    RiscvKbSC,
    dummy_vk_and_chunk_proof_kb,
    dummy_challenger_kb,
    RecursionKbFC,
    RecursionKbSC,
    KoalaBearPoseidon2
);

fn load_vk_map_bb(filename: &str) -> BTreeMap<[BabyBear; DIGEST_SIZE], usize> {
    if let Ok(mut file) = File::open(filename) {
        if let Ok(vk_map) =
            bincode::deserialize_from::<_, BTreeMap<[BabyBear; DIGEST_SIZE], usize>>(&mut file)
        {
            return vk_map;
        }
    }
    BTreeMap::new()
}

fn save_vk_map_bb(
    filename: &str,
    vk_map: &BTreeMap<[BabyBear; DIGEST_SIZE], usize>,
) -> std::io::Result<()> {
    let mut file = File::create(filename)?;
    bincode::serialize_into(&mut file, vk_map)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

fn load_vk_map_kb(filename: &str) -> BTreeMap<[KoalaBear; DIGEST_SIZE], usize> {
    if let Ok(mut file) = File::open(filename) {
        if let Ok(vk_map) =
            bincode::deserialize_from::<_, BTreeMap<[KoalaBear; DIGEST_SIZE], usize>>(&mut file)
        {
            return vk_map;
        }
    }
    BTreeMap::new()
}

fn save_vk_map_kb(
    filename: &str,
    vk_map: &BTreeMap<[KoalaBear; DIGEST_SIZE], usize>,
) -> std::io::Result<()> {
    let mut file = File::create(filename)?;
    bincode::serialize_into(&mut file, vk_map)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
}

/// Load `(ProofShape -> vk_digest)` map from a file.
/// If the file doesn't exist or fails to deserialize, returns an empty map.
pub fn load_riscv_proofshape_map_bb(
    filename: &str,
) -> HashMap<ProofShape, [BabyBear; DIGEST_SIZE]> {
    if let Ok(file) = File::open(filename) {
        if let Ok(map) =
            bincode::deserialize_from::<_, HashMap<ProofShape, [BabyBear; DIGEST_SIZE]>>(&file)
        {
            return map;
        }
    }
    HashMap::new()
}

/// Save `(ProofShape -> vk_digest)` map to a file.
pub fn save_riscv_proofshape_map_bb(
    filename: &str,
    map: &HashMap<ProofShape, [BabyBear; DIGEST_SIZE]>,
) -> io::Result<()> {
    let file = File::create(filename)?;
    bincode::serialize_into(&file, map).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

/// Load `(ProofShape -> vk_digest)` map from a file.
/// If the file doesn't exist or fails to deserialize, returns an empty map.
pub fn load_riscv_proofshape_map_kb(
    filename: &str,
) -> HashMap<ProofShape, [KoalaBear; DIGEST_SIZE]> {
    if let Ok(file) = File::open(filename) {
        if let Ok(map) =
            bincode::deserialize_from::<_, HashMap<ProofShape, [KoalaBear; DIGEST_SIZE]>>(&file)
        {
            return map;
        }
    }
    HashMap::new()
}

/// Save `(ProofShape -> vk_digest)` map to a file.
pub fn save_riscv_proofshape_map_kb(
    filename: &str,
    map: &HashMap<ProofShape, [KoalaBear; DIGEST_SIZE]>,
) -> io::Result<()> {
    let file = File::create(filename)?;
    bincode::serialize_into(&file, map).map_err(|e| io::Error::new(io::ErrorKind::Other, e))
}

macro_rules! define_generate_all_shapes {
    ($func_name:ident, $F:ty) => {
        fn $func_name(
            riscv_shape_config: &RiscvShapeConfig<$F>,
            recursion_shape_config: &RecursionShapeConfig<
                $F,
                RecursionChipType<$F, COMBINE_DEGREE>,
            >,
            merkle_tree_height: usize,
        ) -> Vec<PicoRecursionProgramShape> {
            let riscv_recursion_shapes = riscv_shape_config
                .generate_all_allowed_shapes()
                .map(|shape| PicoRecursionProgramShape::Convert(shape.into()));

            let combine_shapes_2 =
                recursion_shape_config
                    .get_all_shape_combinations(2)
                    .map(|shape| {
                        PicoRecursionProgramShape::Combine(RecursionVkShape::from_proof_shapes(
                            shape,
                            merkle_tree_height,
                        ))
                    });

            let combine_shapes_1 =
                recursion_shape_config
                    .get_all_shape_combinations(1)
                    .map(|shape| {
                        PicoRecursionProgramShape::Combine(RecursionVkShape::from_proof_shapes(
                            shape,
                            merkle_tree_height,
                        ))
                    });

            let compress_shape =
                recursion_shape_config
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

            HashSet::<_>::from_iter(all_shapes).into_iter().collect()
        }
    };
}

define_generate_all_shapes!(generate_all_shapes, BabyBear);
define_generate_all_shapes!(generate_all_shapes_kb, KoalaBear);

#[derive(Debug, Parser)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Specify the field type (e.g., babybear, koalabear)
    #[arg(short, long, default_value_t = FieldEnum::KoalaBear, value_enum)]
    field: FieldEnum,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum FieldEnum {
    BabyBear,
    KoalaBear,
}

macro_rules! generate_vk_map {
    ($F:ty, $generate_all:expr, $load_riscv_proofshape_map:expr, $save_riscv_proofshape_map:expr, $vk_digest_from_shape:expr, $save_vk_map:expr, $proofshape_map_path:expr, $vk_map_path:expr) => {{
        // let riscv_shape_config = RiscvShapeConfig::<$F>::maximal_only();
        let riscv_shape_config = RiscvShapeConfig::<$F>::default();
        let recursion_shape_config =
            RecursionShapeConfig::<$F, RecursionChipType<$F, COMBINE_DEGREE>>::default();

        let shapes_without_height = $generate_all(&riscv_shape_config, &recursion_shape_config, 0);
        let total_num = shapes_without_height.len();
        println!(
            "Total num of all shapes (after deduplication): {}",
            total_num
        );

        let merkle_tree_height = total_num.next_power_of_two().ilog2() as usize;

        let shapes_with_height = $generate_all(
            &riscv_shape_config,
            &recursion_shape_config,
            merkle_tree_height,
        );

        let riscv_cache = $load_riscv_proofshape_map($proofshape_map_path);

        let riscv_cache_arc = Arc::new(RwLock::new(riscv_cache));

        let results: Vec<_> = shapes_with_height
            .par_iter()
            .map(|shape| match shape {
                PicoRecursionProgramShape::Convert(riscv_shape) => {
                    assert_eq!(riscv_shape.proof_shapes.len(), 1);
                    let proof_shape_key = &riscv_shape.proof_shapes[0];

                    // Acquire READ lock first
                    {
                        let cache_reader = riscv_cache_arc.read().unwrap();
                        if let Some(cached) = cache_reader.get(&proof_shape_key) {
                            // If found in cache, just return it
                            return *cached;
                        }
                    }

                    let new_digest = $vk_digest_from_shape(shape.clone());
                    println!("shape: {:?}\nvk_digest: {:?}", shape.clone(), new_digest);

                    {
                        let mut cache_writer = riscv_cache_arc.write().unwrap();
                        cache_writer
                            .entry(proof_shape_key.clone())
                            .or_insert(new_digest);
                    }
                    new_digest
                }
                // For Combine or Compress shapes, call vk_digest_from_shape with no caching
                _ => {
                    let vk_digest = $vk_digest_from_shape(shape.clone());
                    println!("shape: {:?}\nvk_digest: {:?}", shape.clone(), vk_digest);
                    vk_digest
                }
            })
            .collect();

        {
            let cache_reader = riscv_cache_arc.read().unwrap();
            $save_riscv_proofshape_map($proofshape_map_path, &cache_reader)
                .expect("Failed to save riscv_proof_map_kb.bin");
        }

        let vk_set: BTreeSet<_> = results.into_iter().collect();

        let vk_map = vk_set
            .into_iter()
            .enumerate()
            .map(|(i, vk)| (vk, i))
            .collect::<BTreeMap<_, _>>();

        $save_vk_map($vk_map_path, &vk_map).expect("Failed to save updated vk_map_kb.bin");
    }};
}

fn main() {
    let args: Args = Args::parse();

    let field = args.field;
    println!("Field type is: {:?}", field);

    // TODO: remove redundant count (merkle tree height set to 0 for dummy shape count)
    let start_time = std::time::Instant::now();

    // COMBINE_DEGREE == COMPRESS_DEGREE == 3
    match field {
        FieldEnum::BabyBear => {
            generate_vk_map!(
                BabyBear,
                generate_all_shapes,
                load_riscv_proofshape_map_bb,
                save_riscv_proofshape_map_bb,
                vk_digest_from_shape,
                save_vk_map_bb,
                "riscv_proofshape_map_bb.bin",
                "vk_map_bb.bin"
            )
        }
        FieldEnum::KoalaBear => {
            generate_vk_map!(
                KoalaBear,
                generate_all_shapes_kb,
                load_riscv_proofshape_map_kb,
                save_riscv_proofshape_map_kb,
                vk_digest_from_shape_kb,
                save_vk_map_kb,
                "riscv_proofshape_map_kb.bin",
                "vk_map_kb.bin"
            )
        }
    }

    println!("vk_map_kb has been serialized and saved to vk_map_kb.bin");
    let total_time = start_time.elapsed().as_secs_f32();
    println!("Total time for building vk map: {}", total_time);
}
