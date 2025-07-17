//
// pub fn pico_poseidon2kb_init_poseidon2constants() -> (PicoPoseidon2KoalaBear, Poseidon2Constants) {
//     const ROUNDS_F: usize = KOALABEAR_NUM_EXTERNAL_ROUNDS;
//     const ROUNDS_P: usize = KOALABEAR_NUM_INTERNAL_ROUNDS;

//     let mut round_constants = RC_16_30_KoalaBear.to_vec();
//     let internal_start = ROUNDS_F / 2;
//     let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
//     let internal_round_constants = round_constants
//         .drain(internal_start..internal_end)
//         .map(|vec| vec[0])
//         .collect::<Vec<_>>();

//     let internal_constants = internal_round_constants;
//     let initial = round_constants[..(ROUNDS_F / 2)].to_vec();
//     let terminal = round_constants[(ROUNDS_F / 2)..ROUNDS_F].to_vec();
//     let mut external_constants = initial.clone();
//     external_constants.extend(terminal.clone());

//     let p2constant = Poseidon2Constants::new(&external_constants, &internal_constants);

//     let external_layer = ExternalLayerConstants::new(initial.clone(), terminal.clone());
//     let perm = PicoPoseidon2KoalaBear::new(external_layer, internal_constants.clone());
//     (perm, p2constant)
// }

use crate::{
    cuda_adaptor::{gpuacc_struct::fri_commit::HashType, Poseidon2Constants},
    primitives::{
        bn254_from_ark_ff,
        consts::{KOALABEAR_NUM_EXTERNAL_ROUNDS, KOALABEAR_NUM_INTERNAL_ROUNDS},
        RC_16_30_KoalaBear,
    },
};
use p3_bn254_fr::Bn254Fr;
use zkhash::poseidon2::poseidon2_instance_bn256::RC3;

pub fn get_koala_poseidon2_constants() -> Poseidon2Constants {
    const ROUNDS_F: usize = KOALABEAR_NUM_EXTERNAL_ROUNDS;
    const ROUNDS_P: usize = KOALABEAR_NUM_INTERNAL_ROUNDS;

    let mut round_constants = RC_16_30_KoalaBear.to_vec();
    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();

    let external_round_constants = round_constants;
    let p2constant: Poseidon2Constants = Poseidon2Constants::new(
        &external_round_constants[0..ROUNDS_F],
        &internal_round_constants[0..ROUNDS_P],
    );
    p2constant
}
pub fn get_bn254_poseidon2_constants() -> Poseidon2Constants {
    const ROUNDS_F: usize = 8;
    const ROUNDS_P: usize = 56;

    // Copy over round constants from zkhash.
    let mut round_constants: Vec<[Bn254Fr; 3]> = RC3
        .iter()
        .map(|vec| {
            vec.iter()
                .cloned()
                .map(bn254_from_ark_ff)
                .collect::<Vec<_>>()
                .try_into()
                .unwrap()
        })
        .collect();

    let internal_start = ROUNDS_F / 2;
    let internal_end = (ROUNDS_F / 2) + ROUNDS_P;
    let internal_round_constants = round_constants
        .drain(internal_start..internal_end)
        .map(|vec| vec[0])
        .collect::<Vec<_>>();
    let external_round_constants = round_constants;

    let p2constant: Poseidon2Constants = Poseidon2Constants::new(
        &external_round_constants[0..ROUNDS_F],
        &internal_round_constants[0..ROUNDS_P],
    );
    p2constant
}
pub fn get_poseidon2_constants(hash_type: HashType) -> Poseidon2Constants {
    match hash_type {
        HashType::Poseidon2KoalaBear => get_koala_poseidon2_constants(),
        HashType::Poseidon2Bn254 => get_bn254_poseidon2_constants(),
    }
}
