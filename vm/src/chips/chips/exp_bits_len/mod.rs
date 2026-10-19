pub mod columns;
pub mod constraints;
#[cfg(test)]
mod tests;
pub mod traces;

pub use columns::*;
use p3_field::PrimeField32;
use std::marker::PhantomData;

/// The KoalaBear canonicality constraints (`LOW_BITS_COUNT = 24`, high region = 7 bits) are only
/// sound for the KoalaBear modulus `p = 2^31 - 2^24 + 1`. Fail loudly on any other field.
pub(crate) fn assert_koalabear_field<F: PrimeField32>() {
    assert_eq!(
        F::ORDER_U32,
        <p3_koala_bear::KoalaBear as PrimeField32>::ORDER_U32,
        "ExpBitsLenChip is hard-coded for the KoalaBear modulus; canonicality constraints assume \
         p = 2^31 - 2^24 + 1 (LOW_BITS_COUNT = 24, high region = 7 bits)",
    );
}

/// Exponentiation-by-canonical-bit-decomposition chip over the KoalaBear field.
///
/// Canonically bit-decomposes a field element `bit_src` (read from memory) and computes
/// `result = base^(canonical(bit_src) mod 2^num_bits)`, where `base` and `num_bits` are
/// program-fixed (preprocessed) constants. The chip exports the decomposition bits and the
/// result to memory so downstream WHIR verifier logic can consume them.
///
/// Design notes:
///   * Canonicality is checked against the KoalaBear modulus (`LOW_BITS_COUNT = 24`, high
///     region = 7 bits).
///   * `is_first`/`is_last`/`is_real` are baked in the preprocessed trace rather than derived.
///   * A single request occupies a 32-row block; `base`/`num_bits` are injected as preprocessed
///     constants rather than carried on a lookup bus.
#[derive(Clone, Debug, Copy, Default)]
pub struct ExpBitsLenChip<F> {
    pub _phantom: PhantomData<fn(F) -> F>,
}
