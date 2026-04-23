use crate::{
    chips::{
        chips::byte::event::{ByteLookupEvent, ByteRecordBehavior},
        gadgets::u32_to_u8::U32toU8Gadget,
    },
    compiler::riscv::opcode::ByteOpcode,
    machine::builder::ChipLookupBuilder,
};
use p3_field::Field;
use pico_derive::AlignedBorrow;

#[derive(AlignedBorrow, Default, Debug, Clone, Copy)]
#[repr(C)]
pub struct XorU32Gadget<T> {
    /// Lower byte of two limbs of `b`.
    pub b_low_bytes: U32toU8Gadget<T>,

    /// Lower byte of two limbs of `c`.
    pub c_low_bytes: U32toU8Gadget<T>,

    /// The result of the xor operation.
    pub value: [T; 4],
}

impl<F: Field> XorU32Gadget<F> {
    pub fn populate(
        &mut self,
        record: &mut impl ByteRecordBehavior,
        b_u32: u32,
        c_u32: u32,
    ) -> u32 {
        let expected = b_u32 ^ c_u32;
        self.b_low_bytes.populate(b_u32);
        self.c_low_bytes.populate(c_u32);

        let b_bytes = b_u32.to_le_bytes();
        let c_bytes = c_u32.to_le_bytes();
        for i in 0..4 {
            let xor = b_bytes[i] ^ c_bytes[i];
            self.value[i] = F::from_canonical_u8(xor);

            let byte_event = ByteLookupEvent {
                opcode: ByteOpcode::XOR,
                a1: xor as u16,
                a2: 0,
                b: b_bytes[i],
                c: c_bytes[i],
            };
            record.add_byte_lookup_event(byte_event);
        }
        expected
    }

    /// Evaluate the xor operation over two u32s of two u16 limbs.
    /// Assumes that the two words are valid u32s of two u16 limbs.
    /// Constrains that `is_real` is boolean.
    /// If `is_real` is true, the return value is constrained to be correct.
    pub fn eval<CB: ChipLookupBuilder<F>>(
        builder: &mut CB,
        b: [CB::Expr; 2],
        c: [CB::Expr; 2],
        cols: XorU32Gadget<CB::Var>,
        is_real: CB::Var,
    ) -> [CB::Expr; 2] {
        // Constrain that `is_real` is boolean.
        builder.assert_bool(is_real);

        // Convert the two words to bytes using the unsafe API.
        // SAFETY: This is safe because the byte lookup will range check the bytes.
        let b_bytes = U32toU8Gadget::<CB::F>::eval(builder, b, cols.b_low_bytes);
        let c_bytes = U32toU8Gadget::<CB::F>::eval(builder, c, cols.c_low_bytes);

        // Constrain the `XOR` operation over bytes via a byte lookup.
        for i in 0..4 {
            builder.looking_byte(
                CB::F::from_canonical_u32(ByteOpcode::XOR as u32),
                cols.value[i],
                b_bytes[i].clone(),
                c_bytes[i].clone(),
                is_real,
            );
        }

        // Combine the byte results into two u16 limbs.
        let result_limb0 = cols.value[0] + cols.value[1] * CB::F::from_canonical_u32(1 << 8);
        let result_limb1 = cols.value[2] + cols.value[3] * CB::F::from_canonical_u32(1 << 8);

        [result_limb0, result_limb1]
    }
}
