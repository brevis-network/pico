pub mod conversions;
pub mod field_params;
pub mod limbs;
pub mod polynomial;

/// rand 0.10 stand-in for num-bigint's `RandBigInt::gen_biguint` (still pinned to rand 0.8).
#[cfg(test)]
pub trait RandBigUint {
    /// Uniform random `BigUint` with at most `bits` bits.
    fn random_biguint(&mut self, bits: u64) -> num_bigint::BigUint;
}

#[cfg(test)]
impl<R: rand::Rng + ?Sized> RandBigUint for R {
    fn random_biguint(&mut self, bits: u64) -> num_bigint::BigUint {
        let n_bytes = bits.div_ceil(8) as usize;
        let mut bytes = vec![0u8; n_bytes];
        self.fill_bytes(&mut bytes);
        if !bits.is_multiple_of(8) {
            bytes[n_bytes - 1] &= (1u8 << (bits % 8)) - 1;
        }
        num_bigint::BigUint::from_bytes_le(&bytes)
    }
}
