use common::run_proof;

fn main() {
    // The four compressed points the guest commits for these inputs: P = decompress([1; 32]),
    // P + decompress([3; 32]), s*P and s*P + t*G, with s = [2; 32] and t = [4; 32] reduced mod
    // the group order. Computed on the host with crates.io curve25519-dalek-ng 4.1.1.
    run_proof!(
        [ED_ADD, ED_DECOMPRESS],
        commits = common::hex(concat!(
            "0101010101010101010101010101010101010101010101010101010101010101",
            "c111d5bc4b5747e085c137d0299464bab0b0b6138010619beb57d4c9c3e8f7b7",
            "f3a9e5197d1de2419279832bb9686f7d233d37fc1a5ccfc1bc57ce48f46129db",
            "bd28900a23177b9d5ad4b05e58ca44d5c094ada1663e46b91b5a273c812ab44c",
        )),
        [1u8; 32],
        [3u8; 32],
        [2u8; 32],
        [4u8; 32],
    );
}
