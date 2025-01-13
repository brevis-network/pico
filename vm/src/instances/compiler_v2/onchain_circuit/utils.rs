use crate::{
    compiler::recursion_v2::{constraints::Constraint, ir::Witness},
    configs::config::FieldGenericConfig,
};
use std::{fs::File, io::Write, path::PathBuf};

use super::gnark::witness::GnarkWitness;

#[allow(unused)]
pub fn build_gnark_config<EmbedFC: FieldGenericConfig>(
    constraints: Vec<Constraint>,
    witness: Witness<EmbedFC>,
    build_dir: PathBuf,
) {
    let serialized = serde_json::to_string(&constraints).unwrap();

    // Write constraints.
    let constraints_path = build_dir.join("constraints.json");
    let mut file = File::create(constraints_path).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();

    // Write witness.
    let witness_path = build_dir.join("groth16_witness.json");
    let gnark_witness = GnarkWitness::new(witness);
    let mut file = File::create(witness_path).unwrap();
    let serialized = serde_json::to_string(&gnark_witness).unwrap();
    file.write_all(serialized.as_bytes()).unwrap();
}
