use common::run_proof;

fn main() {
    // 3 * 2^65000 mod 2^256 - 8, big-endian: upstream crypto-bigint 0.6.0-rc.6 on the host.
    run_proof!(
        [UINT256_MUL],
        commits = common::hex("0000030000000000000000000000000000000000000000000000000000000000"),
    );
}
