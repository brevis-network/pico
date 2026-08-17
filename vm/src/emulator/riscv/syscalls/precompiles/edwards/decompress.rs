use std::marker::PhantomData;

use crate::chips::gadgets::{
    curves::{
        curve25519_dalek::CompressedEdwardsY,
        edwards::{ed25519::decompress, EdwardsParameters, WORDS_FIELD_ELEMENT},
        COMPRESSED_POINT_BYTES,
    },
    utils::conversions::{bytes_to_words_le, words_to_bytes_le},
};

use crate::emulator::riscv::{
    event_types::RvValue,
    syscalls::{
        precompiles::{EdDecompressEvent, PrecompileEvent},
        syscall_context::SyscallContext,
        Syscall, SyscallCode,
    },
};

pub(crate) struct EdwardsDecompressSyscall<E: EdwardsParameters> {
    _phantom: PhantomData<E>,
}

// Unused: the Edwards syscalls are not registered while their chips are out of the machine.
// Kept so the implementation is ready if they return. See `syscalls/mod.rs`.
#[allow(dead_code)]
impl<E: EdwardsParameters> EdwardsDecompressSyscall<E> {
    /// Create a new instance of the [`EdwardsDecompressSyscall`].
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<E: EdwardsParameters> Syscall for EdwardsDecompressSyscall<E> {
    fn emulate(
        &self,
        ctx: &mut SyscallContext,
        syscall_code: SyscallCode,
        arg1: RvValue,
        arg2: RvValue,
    ) -> Option<RvValue> {
        let start_clk = ctx.clk;
        let slice_ptr = arg1;
        SyscallContext::assert_dword_aligned_precompile(slice_ptr, "edwards decompress slice_ptr");
        let sign =
            u32::try_from(arg2).unwrap_or_else(|_| panic!("ed decompress sign overflow: {}", arg2));
        assert!(sign <= 1, "Sign bit must be 0 or 1.");

        // The Ed25519 point halves are passed as packed u64 arrays on RV64, so each pair of
        // legacy u32 limbs occupies one dword slot in guest memory.
        let num_memory_words = WORDS_FIELD_ELEMENT;
        let y_ptr = slice_ptr + (num_memory_words as u64) * 8;
        let (y_memory_records, y_words) = ctx.mr_dword_slice(y_ptr, num_memory_words);
        let y_vec = y_words
            .iter()
            .flat_map(|&word| [word as u32, (word >> 32) as u32])
            .collect::<Vec<u32>>();

        let sign_bool = sign != 0;

        let y_bytes: [u8; COMPRESSED_POINT_BYTES] = words_to_bytes_le(&y_vec);

        // Copy bytes into another array so we can modify the last byte and make CompressedEdwardsY,
        // which we'll use to compute the expected X.
        // Re-insert sign bit into last bit of Y for CompressedEdwardsY format
        let mut compressed_edwards_y: [u8; COMPRESSED_POINT_BYTES] = y_bytes;
        compressed_edwards_y[compressed_edwards_y.len() - 1] &= 0b0111_1111;
        compressed_edwards_y[compressed_edwards_y.len() - 1] |= (sign as u8) << 7;

        // Compute actual decompressed X
        let compressed_y = CompressedEdwardsY(compressed_edwards_y);
        let decompressed =
            decompress(&compressed_y).expect("Decompression failed, syscall invariant violated.");

        let mut decompressed_x_bytes = decompressed.x.to_bytes_le();
        decompressed_x_bytes.resize(32, 0u8);
        let decompressed_x_words: [u32; WORDS_FIELD_ELEMENT * 2] =
            bytes_to_words_le(&decompressed_x_bytes);

        // Write decompressed X into slice
        let decompressed_x_dwords = decompressed_x_words
            .chunks_exact(2)
            .map(|pair| u64::from(pair[0]) | (u64::from(pair[1]) << 32))
            .collect::<Vec<u64>>();
        let x_memory_records = ctx.mw_dword_slice(slice_ptr, &decompressed_x_dwords);

        let chunk = ctx.current_chunk();
        let event = EdDecompressEvent {
            chunk,
            clk: start_clk,
            ptr: arg1,
            sign: sign_bool,
            y_words: y_words.try_into().unwrap(),
            decompressed_x_words: decompressed_x_dwords.try_into().unwrap(),
            x_memory_records: x_memory_records.try_into().unwrap(),
            y_memory_records: y_memory_records.try_into().unwrap(),
            local_mem_access: ctx.postprocess(),
        };
        let syscall_event = ctx
            .rt
            .syscall_event(start_clk, syscall_code.syscall_id(), arg1, arg2);
        ctx.record_mut().add_precompile_event(
            syscall_code,
            syscall_event,
            PrecompileEvent::EdDecompress(event),
        );
        None
    }

    fn num_extra_cycles(&self) -> u32 {
        0
    }
}
