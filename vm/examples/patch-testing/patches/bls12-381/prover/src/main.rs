use common::run_proof;

fn main() {
    // For the app's 16 iterations: 17 * G uncompressed, 2^16 * G uncompressed, then 17 * G
    // compressed, from upstream bls12_381 0.8.0 on the host: projective arithmetic converted to
    // affine, each cross-checked against scalar multiplication.
    let commits = common::hex(concat!(
        "1098f178f84fc753a76bb63709e9be91eec3ff5f7f3a5f4836f34fe8a1a6d6c5578d8fd820573cef3a01e2bfef3eaf3a",
        "0ea923110b733b531006075f796cc9368f2477fe26020f465468efbb380ce1f8eebaf5c770f31d320f9bd378dc758436",
        "0494bff563fd1259a04b868f64e0472e2d1f48ff0a02a3142effe17df01f8611146e1218235837868b42963637a4e769",
        "04577345056006f7dde74849e1e18a57965e1c2d6612461787c870cdfe8d14c51f7b749495ae5c5eabd03e1286a1a437",
        "b098f178f84fc753a76bb63709e9be91eec3ff5f7f3a5f4836f34fe8a1a6d6c5578d8fd820573cef3a01e2bfef3eaf3a",
    ));
    run_proof!(
        [
            BLS12381_ADD,
            BLS12381_DOUBLE,
            BLS12381_FP_ADD,
            BLS12381_FP_SUB,
            BLS12381_FP_MUL,
            BLS12381_FP2_MUL
        ],
        commits = commits,
    );
}
