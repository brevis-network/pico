use common::run_proof;

fn main() {
    // 6001 * G uncompressed, 2^6000 * G uncompressed, then 6001 * G compressed, from upstream
    // bls12_381 0.8.0 on the host: projective arithmetic converted to affine, each cross-checked
    // against scalar multiplication.
    let commits = common::hex(concat!(
        "06ba2960ab2b1dd5adb60cf903a5951562af11ab8f56b9dc86cb1a3bdb9f8d14edfd69cc17a5596d3b7b544dac3b7479",
        "0e4414150be5c8fe1035f52e1cae37cdd6fd54b48be8f35e61526ac6e5c6e28f4d8f477ecd29216c4a0cf1f262952aed",
        "124b9b5b04f865c675962db2b7b5bd8c3f1227051eea6aec95d8f939377c521cb3d2918b9b9ce229c773c4893e552da7",
        "0b3377a1f6d5ceb225fdcf56b3fc2ede80af16a58fe9d7385e08bbe7cb9ffd85802db43291da02ab131fed1bf2e2546c",
        "a6ba2960ab2b1dd5adb60cf903a5951562af11ab8f56b9dc86cb1a3bdb9f8d14edfd69cc17a5596d3b7b544dac3b7479",
    ));
    run_proof!(
        [
            BLS12381_ADD,
            BLS12381_DOUBLE,
            BLS12381_FP_ADD,
            BLS12381_FP2_MUL
        ],
        commits = commits,
    );
}
