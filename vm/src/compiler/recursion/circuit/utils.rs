use crate::{
    compiler::{
        recursion::ir::{Builder, Felt, Var},
        word::Word,
    },
    configs::config::FieldGenericConfig,
    primitives::consts::NUM_BITS,
};
use p3_field::PrimeCharacteristicRing;

/// Decompose `byte` into its canonical little-endian bits **and prove that it really is a byte**,
/// i.e. that its canonical value lies in `[0, 256)`.
///
/// `num2bits_f_circuit` lowers to `DslIr::CircuitNum2BitsF` -> gnark opcode `Num2BitsF` ->
/// `fieldAPI.ToBinary(felt)` = `api.ToBinary(ReduceSlow(felt).Value, NUM_BITS)`
/// (`gnark/koalabear/koalabear.go:331`). `ReduceSlow` proves the
/// operand is *canonical* (`< p < 2^31`) and `api.ToBinary` boolean-constrains every returned bit
/// and asserts the recomposition. The returned `NUM_BITS` bits are therefore THE canonical binary
/// expansion of the felt, uniquely determined by it -- nothing the prover can choose.
///
/// Consequently "bits `8..NUM_BITS` are all zero" is exactly the range check `felt < 256`.
///
/// The high bits are folded into a single linear combination
/// `sum_{j=0}^{NUM_BITS-9} 2^j * bit_{8+j}` before one equality assert, rather than asserting each
/// bit individually. This is sound *because* the bits are already boolean-constrained: the sum is
/// bounded by `2^(NUM_BITS-8) - 1 = 2^23 - 1`, which is far below the Bn254 scalar modulus, so it
/// cannot wrap and can only vanish when every high bit is zero. Cost: 1 R1CS constraint per byte
/// instead of 23.
pub(crate) fn felt_to_byte_bits<FC: FieldGenericConfig>(
    builder: &mut Builder<FC>,
    byte: Felt<FC::F>,
    zero_var: Var<FC::N>,
) -> Vec<Var<FC::N>> {
    let byte_bits = builder.num2bits_f_circuit(byte);
    debug_assert_eq!(byte_bits.len(), NUM_BITS);
    // Range check: the canonical value of `byte` must fit in 8 bits.
    let high_bits = builder.bits2num_v_circuit(&byte_bits[8..]);
    builder.assert_var_eq(high_bits, zero_var);
    byte_bits
}

pub fn felt_bytes_to_bn254_var<FC: FieldGenericConfig>(
    builder: &mut Builder<FC>,
    bytes: &[Felt<FC::F>; 32],
) -> Var<FC::N> {
    let var_256: Var<_> = builder.constant(FC::N::from_u32(256));
    let zero_var: Var<_> = builder.constant(FC::N::ZERO);
    let result = builder.constant(FC::N::ZERO);
    for (i, byte) in bytes.iter().enumerate() {
        // Constrains each limb to `[0, 256)`. Without this the base-256 accumulation below is not
        // injective: a limb may carry up to `NUM_BITS` bits, `256^31 = 2^248` already exceeds the
        // Bn254 modulus, and a malicious prover can wrap the accumulator onto a chosen digest.
        let byte_bits = felt_to_byte_bits(builder, *byte, zero_var);
        if i == 0 {
            // Since 32 bytes doesn't fit into Bn254, we need to truncate the top 3 bits.
            // For first byte, zero out 3 most significant bits.
            for i in 0..3 {
                builder.assign(byte_bits[8 - i - 1], zero_var);
            }
            let byte_var = builder.bits2num_v_circuit(&byte_bits);
            builder.assign(result, byte_var);
        } else {
            let byte_var = builder.bits2num_v_circuit(&byte_bits);
            builder.assign(result, result * var_256 + byte_var);
        }
    }
    result
}

pub fn words_to_bytes<T: Copy>(words: &[Word<T>]) -> Vec<T> {
    words.iter().flat_map(|w| w.0).collect::<Vec<_>>()
}
