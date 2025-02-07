use crate::{
    compiler::recursion::{constraints::Constraint, ir::Witness},
    configs::config::FieldGenericConfig,
};
use std::{fs::File, io::Write, path::PathBuf};

use super::gnark::witness::GnarkWitness;

const CONSTRAINTS_JSON_FILE: &str = "constraints.json";
const GROTH16_JSON_FILE: &str = "groth16_witness.json";

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
