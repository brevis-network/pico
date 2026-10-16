//! `ProgramId` as an on-chain verifier takes it.

use crate::prover::ProgramId;

/// Bit `pos` of a 32-byte big-endian integer.
fn bit(bytes: &[u8; 32], pos: usize) -> u32 {
    u32::from(bytes[31 - pos / 8] >> (pos % 8) & 1)
}

/// The words come back out of the 32 bytes as 31-bit fields, the first word highest, above eight
/// zero bits: the packing is exact and injective on KoalaBear words.
#[test]
fn vkey_hash_packs_the_words_base_2_31() {
    use pico_mle_core::p3_field::PrimeField32;

    let top = crate::types::Kb::ORDER_U32 - 1;
    let words = [top, 0, 1, 1 << 30, 0x1234_5678, top - 1, 7, 1 << 24];
    let bytes = ProgramId::from_words(words).vkey_hash();

    for (i, &word) in words.iter().enumerate() {
        let base = 31 * (7 - i);
        let field = (0..31).fold(0u32, |acc, b| acc | bit(&bytes, base + b) << b);
        assert_eq!(field, word, "word {i}");
    }
    assert_eq!(
        bytes[0], 0,
        "8 x 31 = 248 bits; the top byte is always zero"
    );
    assert_eq!(ProgramId::from_words([0; 8]).vkey_hash(), [0; 32]);
}

/// A printed id is the on-chain `vkey_hash`, not the eight words it packs.
#[test]
fn a_program_id_displays_as_its_vkey_hash() {
    let id = ProgramId::from_words([1, 0, 0, 0, 0, 0, 0, 2]);
    let hex: String = id.vkey_hash().iter().map(|b| format!("{b:02x}")).collect();
    assert_eq!(id.to_string(), format!("0x{hex}"));
    assert_eq!(format!("{id:?}"), format!("ProgramId(0x{hex})"));
    assert_eq!(id.to_string().len(), 2 + 64);
}

/// A stored id is eight canonical words, because past the modulus two ids can pack to one hash:
/// `[0, .., 0, 2^31]` and `[0, .., 1, 0]` both print as `0x..80000000`.
#[test]
fn a_stored_id_past_the_modulus_is_refused() {
    use pico_mle_core::p3_field::PrimeField32;

    let order = crate::types::Kb::ORDER_U32;
    let mut forged = [0; 8];
    forged[7] = 1 << 31;
    let mut honest = [0; 8];
    honest[6] = 1;
    assert_eq!(
        ProgramId::from_words(forged).vkey_hash(),
        ProgramId::from_words(honest).vkey_hash()
    );

    assert!(ProgramId::from_stored_words(forged).is_err());
    assert!(ProgramId::from_stored_words([0, 0, 0, order, 0, 0, 0, 0]).is_err());
    assert!(ProgramId::from_stored_words([order - 1; 8]).is_ok());
    assert!(ProgramId::from_stored_words(honest).is_ok());
}
