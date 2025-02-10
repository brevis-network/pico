use pico_sdk::client::BabyBearProveClient;
use pico_sdk::init_logger;
use tendermint_light_client_verifier::{options::Options, ProdVerifier, Verdict, Verifier};

use std::error::Error;

use std::{fs, fs::File, io::Read, time::Duration};

use tendermint_light_client_verifier::types::LightBlock;

fn get_light_blocks() -> (LightBlock, LightBlock) {
    let light_block_1 = load_light_block(2279100).expect("Failed to generate light block 1");
    let light_block_2 = load_light_block(2279130).expect("Failed to generate light block 2");
    (light_block_1, light_block_2)
}

pub fn load_light_block(block_height: u64) -> Result<LightBlock, Box<dyn Error>> {
    let mut file = File::open(format!("files/block_{}.json", block_height))?;
    let mut block_response_raw = String::new();
    file.read_to_string(&mut block_response_raw)
        .unwrap_or_else(|_| panic!("Failed to read block number {}", block_height));
    Ok(serde_json::from_str(&block_response_raw)?)
}

fn main() {
    // Initialize logger
    init_logger();

    // Load the ELF file
    let elf = load_elf("./elf/riscv32im-pico-zkvm-elf");
    println!("elf length: {}", elf.len());

    let client = BabyBearProveClient::new(&elf);
    let stdin_builder = client.get_stdin_builder(); // Shared instance

    // Load light blocks from the `files` subdirectory
    let (light_block_1, light_block_2) = get_light_blocks();

    let expected_verdict = verify_blocks(light_block_1.clone(), light_block_2.clone());

    let encoded_1 = serde_cbor::to_vec(&light_block_1).unwrap();
    let encoded_2 = serde_cbor::to_vec(&light_block_2).unwrap();

    println!("encode_1 length: {}", encoded_1.len());
    println!("encode_2 length: {}", encoded_2.len());

    stdin_builder.borrow_mut().write_slice(&encoded_1);
    stdin_builder.borrow_mut().write_slice(&encoded_2);

    let proof = client.prove_fast().expect("proving failed");

    // Verify the public values
    let mut expected_public_values: Vec<u8> = Vec::new();
    expected_public_values.extend(light_block_1.signed_header.header.hash().as_bytes());
    expected_public_values.extend(light_block_2.signed_header.header.hash().as_bytes());
    expected_public_values.extend(serde_cbor::to_vec(&expected_verdict).unwrap());

    assert_eq!(proof.pv_stream.unwrap(), expected_public_values);

    println!("successfully generated and verified proof for the program!")
}

fn verify_blocks(light_block_1: LightBlock, light_block_2: LightBlock) -> Verdict {
    let vp = ProdVerifier::default();
    let opt = Options {
        trust_threshold: Default::default(),
        trusting_period: Duration::from_secs(500),
        clock_drift: Default::default(),
    };
    let verify_time = light_block_2.time() + Duration::from_secs(20);
    vp.verify_update_header(
        light_block_2.as_untrusted_state(),
        light_block_1.as_trusted_state(),
        &opt,
        verify_time.unwrap(),
    )
}

/// Loads an ELF file from the specified path.
pub fn load_elf(path: &str) -> Vec<u8> {
    fs::read(path).unwrap_or_else(|err| {
        panic!("Failed to load ELF file from {}: {}", path, err);
    })
}
