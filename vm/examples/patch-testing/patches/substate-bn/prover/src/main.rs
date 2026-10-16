use common::run_proof;

fn main() {
    // The big-endian x-coordinates of 6001 * G and 2^6000 * G, from upstream substrate-bn 0.6.0 on
    // the host: Jacobian arithmetic converted to affine, each cross-checked against scalar
    // multiplication.
    let commits = common::hex(concat!(
        "1989717cd787a8aa374bb14212b72fa85e3b2667bc66f4f928b3e213b6f63e1d",
        "0bb5351414f358380b50fecf6731a6f908981d75a140cc01d6c157b425efed90",
    ));
    run_proof!(
        [BN254_ADD, BN254_DOUBLE, BN254_FP_ADD, BN254_FP2_MUL],
        commits = commits,
    );
}
