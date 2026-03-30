use crate::{
    compiler::addr::encode_proof_addr_to_u32_limbs_48,
    emulator::riscv::event_types::{RvAddr, RvChunk},
};

/// Retained proof/public-value encoders for the current 48-bit proof-address and u32 chunk
/// contracts. These are intentional boundaries, not migration leftovers.
#[inline(always)]
pub fn encode_public_value_pc_limbs(pc: RvAddr) -> [u32; 3] {
    encode_proof_addr_to_u32_limbs_48(pc, "public value pc")
}

#[inline(always)]
pub fn encode_public_value_chunk_counter(chunk: RvChunk) -> u32 {
    // PublicValues intentionally stores chunk counters as u32 in the retained proof/public-value
    // schema for this RV64IM tranche.
    chunk
}

#[cfg(test)]
mod tests {
    use super::{encode_public_value_chunk_counter, encode_public_value_pc_limbs};

    #[test]
    fn encode_pc_limbs() {
        assert_eq!(
            encode_public_value_pc_limbs(0x1234_5678),
            [0x5678, 0x1234, 0]
        );
        assert_eq!(
            encode_public_value_pc_limbs(0xABCD_1234_5678),
            [0x5678, 0x1234, 0xABCD]
        );
    }

    #[test]
    #[should_panic(expected = "frozen 48-bit proof address contract")]
    fn encode_pc_limbs_rejects_values_above_48_bits() {
        let _ = encode_public_value_pc_limbs(1u64 << 48);
    }

    #[test]
    fn encode_chunk_passthrough() {
        assert_eq!(encode_public_value_chunk_counter(7), 7);
    }
}
