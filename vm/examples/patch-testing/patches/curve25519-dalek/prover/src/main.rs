use common::run_proof;

fn main() {
    run_proof!(
        "../app/elf/riscv32im-pico-zkvm-elf",
        [1u8; 32],
        [3u8; 32],
        [2u8; 32],
        [4u8; 32],
    );
}
