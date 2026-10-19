use crate::{compiler::recursion::ir::Witness, configs::config::FieldGenericConfig};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField};
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
    /// Marks a wrap witness so the gnark interpreter picks the MLE KoalaBear-Poseidon2 constants.
    /// Omitted for the FRI path.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend: Option<String>,
    pub _config: PhantomData<EmbedFC>,
}

impl<EmbedFC: FieldGenericConfig> GnarkWitness<EmbedFC> {
    /// Creates a new witness from a given [Witness].
    pub fn new(mut witness: Witness<EmbedFC>) -> Self {
        witness.vars.push(EmbedFC::N::from_usize(999));
        witness.felts.push(EmbedFC::F::from_usize(999));
        witness.exts.push(EmbedFC::EF::from_usize(999));
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
                    w.as_basis_coefficients_slice()
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
            backend: witness.backend,
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
