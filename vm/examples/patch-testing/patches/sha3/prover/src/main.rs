use common::run_proof;

fn main() {
    run_proof!("../app/elf/riscv32im-pico-zkvm-elf", [3u8; 32], [1u8; 32]);
}
