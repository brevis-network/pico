use pico_sdk::{client::BabyBearProverClient, init_logger, HashableKey};
use std::fs;

/// Loads an ELF file from the specified path.
pub fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}

fn main() {
    // Initialize logger
    init_logger();

    println!("----------------------FIBONACCI 1---------------------------------------");
    let elf = load_elf("../../fibonacci/app/elf/riscv32im-pico-zkvm-elf");

    // Initialize the prover client
    let client = BabyBearProverClient::new(&elf);
    // Initialize new stdin
    let mut stdin_builder = client.new_stdin_builder();

    // Set up input
    let n = 10u32;
    stdin_builder.write(&n);

    // Generate proof
    let (riscv_proof, combine_proof_1) = client
        .prove_combine(stdin_builder)
        .expect("Failed to generate proof");

    // Decodes public values from the proof's public value stream.
    let public_buffer_1 = riscv_proof.pv_stream.unwrap();
    let fibonacci_vk_1 = client.riscv_vk();
    let fibo_vk_digest_1 = fibonacci_vk_1.hash_u32();
    println!("Fibonacci fibonacci_vk_digest: {:?}", fibo_vk_digest_1);
    println!("Public buffer: {:?}", public_buffer_1);

    println!("----------------------FIBONACCI 2---------------------------------------");
    let elf = load_elf("../../fibonacci/app/elf/riscv32im-pico-zkvm-elf");

    // Initialize the prover client
    let client = BabyBearProverClient::new(&elf);
    // Initialize new stdin
    let mut stdin_builder = client.new_stdin_builder();

    // Set up input
    let n = 20u32;
    stdin_builder.write(&n);

    // Generate proof
    let (riscv_proof, combine_proof_2) = client
        .prove_combine(stdin_builder)
        .expect("Failed to generate proof");

    // Decodes public values from the proof's public value stream.
    let public_buffer_2 = riscv_proof.pv_stream.unwrap();
    let fibonacci_vk_2 = client.riscv_vk();
    let fibo_vk_digest_2 = fibonacci_vk_2.hash_u32();
    println!("Fibonacci fibonacci_vk_digest: {:?}", fibo_vk_digest_2);
    println!("Public buffer: {:?}", public_buffer_2);

    println!("----------------------Aggregator--------------------------------------");

    // Load the ELF file
    let elf = load_elf("../app/elf/riscv32im-pico-zkvm-elf");

    // Initialize the prover client
    let client = BabyBearProverClient::new(&elf);
    // Initialize new stdin
    let mut stdin_builder = client.new_stdin_builder();

    let vk_digests: Vec<[u32; 8]> = [fibo_vk_digest_1, fibo_vk_digest_2].to_vec();
    let public_values: Vec<Vec<u8>> = [public_buffer_1, public_buffer_2].to_vec();
    // TODO: uncomment the following as a soundness check (deferred proof number mismatch, i.e, more deferred proof)
    // let vk_digests: Vec<[u32; 8]> = [fibo_vk_digest_1].to_vec();
    // let public_values: Vec<Vec<u8>> = [public_buffer_1].to_vec();

    // Set up input
    stdin_builder.write(&vk_digests);
    stdin_builder.write(&public_values);
    stdin_builder.write_pico_proof(combine_proof_1.clone(), fibonacci_vk_1.clone());
    stdin_builder.write_pico_proof(combine_proof_2.clone(), fibonacci_vk_2.clone());
    let proof_pvs = combine_proof_1
        .proofs
        .first()
        .unwrap()
        .public_values
        .clone();
    println!("proof_pvs 1: {:?}", proof_pvs);

    let proof_pvs = combine_proof_2
        .proofs
        .first()
        .unwrap()
        .public_values
        .clone();
    println!("proof_pvs 2: {:?}", proof_pvs);

    // Generate proof
    let proof = client
        .prove_combine(stdin_builder)
        .expect("Failed to generate proof");

    println!("Aggregation Finished!");
}
