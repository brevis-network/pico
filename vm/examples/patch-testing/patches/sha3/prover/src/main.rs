use common::run_proof;

fn main() {
    // SHA3-256 of [3; 32]: upstream sha3 0.10.8 on the host.
    run_proof!(
        [KECCAK_PERMUTE],
        commits = common::hex("b4a856909aaea0085e8ceddabe553143ae6bdd13b651aba803df12e6d94b8c07"),
        [3u8; 32],
    );
}
