use common::run_proof;

fn main() {
    // The guest asserts its own result and commits nothing.
    run_proof!(
        [SECP256K1_ADD, SECP256K1_DOUBLE, KECCAK_PERMUTE],
        commits = b""
    );
}
