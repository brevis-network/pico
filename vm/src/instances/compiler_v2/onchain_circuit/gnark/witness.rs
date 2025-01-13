use crate::{compiler::recursion_v2::ir::Witness, configs::config::FieldGenericConfig};
use p3_field::{FieldAlgebra, FieldExtensionAlgebra, PrimeField};
use serde::{Deserialize, Serialize};
use std::{fs::File, io::Write, marker::PhantomData};

/// A witness that can be used to initialize values for witness generation inside Gnark.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct GnarkWitness<EmbedFC> {
    pub vars: Vec<String>,
    pub felts: Vec<String>,
    pub exts: Vec<Vec<String>>,
    pub vkey_hash: String,
    pub committed_values_digest: String,
    pub _config: PhantomData<EmbedFC>,
}

impl<EmbedFC: FieldGenericConfig> GnarkWitness<EmbedFC> {
    /// Creates a new witness from a given [Witness].
    pub fn new(mut witness: Witness<EmbedFC>) -> Self {
        witness.vars.push(EmbedFC::N::from_canonical_usize(999));
        witness.felts.push(EmbedFC::F::from_canonical_usize(999));
        witness.exts.push(EmbedFC::EF::from_canonical_usize(999));
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
                        .map(|x: &EmbedFC::F| x.as_canonical_biguint().to_string())
                        .collect()
                })
                .collect(),
            vkey_hash: witness.vkey_hash.as_canonical_biguint().to_string(),
            committed_values_digest: witness
                .committed_values_digest
                .as_canonical_biguint()
                .to_string(),
            _config: PhantomData,
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
