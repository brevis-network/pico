use common::run_proof;

fn main() {
    // Keccak-256 of [1; 32]: upstream tiny-keccak 2.0.2 on the host.
    run_proof!(
        [KECCAK_PERMUTE],
        commits = common::hex("cebc8882fecbec7fb80d2cf4b312bec018884c2d66667c67a90508214bd8bafc"),
        [1u8; 32],
    );
}
