use crate::{
    compiler::recursion::{constraints::Constraint, ir::Witness},
    configs::config::FieldGenericConfig,
};
use log::info;
use num::Num;
use num_bigint::BigInt;
use serde_json::json;

use std::{
    fs::{self, File},
    io::{BufReader, Write},
    path::PathBuf,
};

use super::gnark::witness::GnarkWitness;
use anyhow::{Error, Ok, Result};

const CONSTRAINTS_JSON_FILE: &str = "constraints.json";
const GROTH16_JSON_FILE: &str = "groth16_witness.json";
const PV_FILE: &str = "pv_file";
const PROOF_FILE: &str = "proof.data";
const CONTRACT_INPUTS_FILE: &str = "inputs.json";

#[allow(unused)]
pub fn build_gnark_config<EmbedFC: FieldGenericConfig>(
    constraints: Vec<Constraint>,
    witness: Witness<EmbedFC>,
    build_dir: PathBuf,
) {
    let serialized = serde_json::to_string(&constraints).unwrap();

    // Write constraints.
    let constraints_path = build_dir.join(CONSTRAINTS_JSON_FILE);
    let mut file = File::create(constraints_path).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();

    // Write witness.
    let witness_path = build_dir.join(GROTH16_JSON_FILE);
    let gnark_witness = GnarkWitness::new(witness);
    let mut file = File::create(witness_path).unwrap();
    let serialized = serde_json::to_string(&gnark_witness).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
}

pub fn generate_contract_inputs<EmbedFC: FieldGenericConfig>(
    pico_out_dir: PathBuf,
) -> Result<PathBuf, Error> {
    info!("Start to generate contract inputs...");
    let proof_path = pico_out_dir.join(PROOF_FILE);
    if !proof_path.exists() {
        return Err(anyhow::anyhow!(
            "the proof file is not exists in {}",
            proof_path.display()
        ));
    }

    let witness_path = pico_out_dir.join(GROTH16_JSON_FILE);
    if !witness_path.exists() {
        return Err(anyhow::anyhow!(
            "the witness file is not exists in {}",
            witness_path.display()
        ));
    }

    // crate inputs.json file
    let contract_input_path = pico_out_dir.join(CONTRACT_INPUTS_FILE);
    let mut contract_input_file = File::create(contract_input_path.clone())?;

    // get vkey_hash from witness file
    let witness_file = File::open(witness_path)?;
    let winess_reader = BufReader::new(witness_file);
    let witness_data: GnarkWitness<EmbedFC> = serde_json::from_reader(winess_reader)?;
    let vkey_hash_bigint = BigInt::from_str_radix(witness_data.vkey_hash.as_str(), 10)?;
    let vkey_hex_string = format!("{:x}", vkey_hash_bigint);
    let vkey_hex = format!("0x{:0>64}", vkey_hex_string);

    // get proof from proof.data
    let proof_file = pico_out_dir.join(PROOF_FILE);
    if !proof_file.exists() {
        return Err(anyhow::anyhow!(
            "the proof.data is not exists in {}",
            pico_out_dir.display()
        ));
    }
    let proof_data = fs::read_to_string(proof_file)?;
    let proof_slice: Vec<String> = proof_data.split(",").map(|s| s.to_string()).collect();
    let proof = &proof_slice[0..8];

    // get pv stream from pv file
    let pv_file_path = pico_out_dir.join(PV_FILE);
    if !pv_file_path.exists() {
        return Err(anyhow::anyhow!(
            "The pv_file is not exists in {}",
            pv_file_path.display()
        ));
    }
    let pv_file_content = fs::read_to_string(pv_file_path)?;
    let pv_string = pv_file_content.trim();
    if !pv_string[2..].chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow::anyhow!(
            "Invalid hex format or length. Expected 64-character hex string."
        ));
    }

    let result_json = json!({
        "riscvVKey": vkey_hex,
        "proof": proof,
        "publicValues":pv_string.to_string()
    });

    let json_string = serde_json::to_string_pretty(&result_json)?;
    contract_input_file.write_all(json_string.as_bytes())?;

    Ok(contract_input_path)
}
