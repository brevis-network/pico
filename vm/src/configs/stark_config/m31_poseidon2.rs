use crate::{
    configs::config::{Com, StarkGenericConfig, Val, ZeroCommitment},
    primitives::{consts::DIGEST_SIZE, PicoPoseidon2Mersenne31, Poseidon2Init},
};
use p3_challenger::DuplexChallenger;
use p3_circle::CirclePcs;
use p3_commit::{ExtensionMmcs, Pcs};
use p3_field::{extension::BinomialExtensionField, Field, FieldAlgebra};
use p3_fri::FriConfig;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_mersenne_31::Mersenne31;
use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, TruncatedPermutation};
use serde::Serialize;
use std::marker::PhantomData;

pub type SC_Val = Mersenne31;
pub type SC_Perm = PicoPoseidon2Mersenne31;
pub type SC_Hash = PaddingFreeSponge<SC_Perm, 16, 8, 8>;
pub type SC_Compress = TruncatedPermutation<SC_Perm, 2, 8, 16>;
pub type SC_ValMmcs =
    MerkleTreeMmcs<<SC_Val as Field>::Packing, <SC_Val as Field>::Packing, SC_Hash, SC_Compress, 8>;
pub type SC_Challenge = BinomialExtensionField<SC_Val, 3>;
pub type SC_ChallengeMmcs = ExtensionMmcs<SC_Val, SC_Challenge, SC_ValMmcs>;

pub type SC_Challenger = DuplexChallenger<SC_Val, SC_Perm, 16, 8>;
pub type SC_Pcs = CirclePcs<SC_Val, SC_ValMmcs, SC_ChallengeMmcs>;
pub type SC_DigestHash = p3_symmetric::Hash<SC_Val, SC_Val, DIGEST_SIZE>;

#[derive(Clone)]
pub struct M31Poseidon2 {
    pub perm: SC_Perm,
    val_mmcs: SC_ValMmcs,
}

impl Serialize for M31Poseidon2 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        std::marker::PhantomData::<M31Poseidon2>.serialize(serializer)
    }
}

impl StarkGenericConfig for M31Poseidon2 {
    type Val = SC_Val;
    type Domain = <SC_Pcs as Pcs<SC_Challenge, SC_Challenger>>::Domain;
    type Challenge = SC_Challenge;
    type Challenger = SC_Challenger;
    type Pcs = SC_Pcs;

    fn new() -> Self {
        let perm = Self::init();
        let hash = SC_Hash::new(perm.clone());
        let compress = SC_Compress::new(perm.clone());
        let val_mmcs = SC_ValMmcs::new(hash, compress);
        Self { perm, val_mmcs }
    }

    /// Targeting 100 bits of security.
    fn pcs(&self) -> Self::Pcs {
        SC_Pcs {
            mmcs: self.val_mmcs.clone(),
            fri_config: FriConfig {
                log_blowup: 1,
                num_queries: 84,
                proof_of_work_bits: 16,
                mmcs: SC_ChallengeMmcs::new(self.val_mmcs.clone()),
            },
            _phantom: PhantomData,
        }
    }

    fn challenger(&self) -> Self::Challenger {
        SC_Challenger::new(self.perm.clone())
    }

    fn name(&self) -> String {
        "M31Poseidon2".to_string()
    }

    fn hash_slice(&self, input: &[Val<Self>]) -> [Val<Self>; DIGEST_SIZE] {
        let hash = SC_Hash::new(self.perm.clone());
        hash.hash_slice(input)
    }
}

impl ZeroCommitment<M31Poseidon2> for SC_Pcs {
    fn zero_commitment(&self) -> Com<M31Poseidon2> {
        SC_DigestHash::from([SC_Val::ZERO; DIGEST_SIZE])
    }
}
