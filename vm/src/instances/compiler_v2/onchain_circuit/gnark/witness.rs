use crate::{
    compiler::recursion_v2::ir::Witness, configs::config::FieldGenericConfig,
    instances::configs::embed_config::FieldConfig as EmbedFC,
};
use p3_baby_bear::BabyBear;
use p3_field::{FieldAlgebra, FieldExtensionAlgebra, PrimeField};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write};

/// A witness that can be used to initialize values for witness generation inside Gnark.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GnarkWitness {
    pub vars: Vec<String>,
    pub felts: Vec<String>,
    pub exts: Vec<Vec<String>>,
    pub vkey_hash: String,
    pub committed_values_digest: String,
}

impl GnarkWitness {
    /// Creates a new witness from a given [Witness].
    pub fn new(mut witness: Witness<EmbedFC>) -> Self {
        witness
            .vars
            .push(<EmbedFC as FieldGenericConfig>::N::from_canonical_usize(
                999,
            ));
        witness
            .felts
            .push(<EmbedFC as FieldGenericConfig>::F::from_canonical_usize(
                999,
            ));
        witness
            .exts
            .push(<EmbedFC as FieldGenericConfig>::EF::from_canonical_usize(
                999,
            ));
        GnarkWitness {
            vars: witness
                .vars
                .into_iter()
                .map(|w| w.as_canonical_biguint().to_string())
                .collect(),
            felts: witness
                .felts
                .into_iter()
                .map(|w| w.as_canonical_biguint().to_string())
                .collect(),
            exts: witness
                .exts
                .into_iter()
                .map(|w| {
                    w.as_base_slice()
                        .iter()
                        .map(|x: &BabyBear| x.as_canonical_biguint().to_string())
                        .collect()
                })
                .collect(),
            vkey_hash: witness.vkey_hash.as_canonical_biguint().to_string(),
            committed_values_digest: witness
                .committed_values_digest
                .as_canonical_biguint()
                .to_string(),
        }
    }

    /// Saves the witness to a given path.
    #[allow(unused)]
    pub fn save(&self, path: &str) {
        let serialized = serde_json::to_string(self).unwrap();
        let mut file = File::create(path).unwrap();
        file.write_all(serialized.as_bytes()).unwrap();
    }
}
