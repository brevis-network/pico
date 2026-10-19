use crate::{
    compiler::recursion::{ir::Block, types::*},
    emulator::recursion::{emulator::*, public_values::RecursionPublicValues},
    primitives::consts::EXTENSION_DEGREE,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};
use std::borrow::Borrow;

/// The instruction set, named once.
///
/// Generates [`InstructionKind`] and [`Instruction::kind`] from a single list, so a variant added
/// to [`Instruction`] fails to compile until it is named here — the profile's table can gain a row
/// but cannot silently lose one.
macro_rules! instruction_kinds {
    ($($variant:ident),+ $(,)?) => {
        /// Which [`Instruction`] variant, without its payload. The key of the recursion
        /// interpreter's per-kind counters and timers.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum InstructionKind {
            $($variant),+
        }

        impl InstructionKind {
            /// Every kind in discriminant order, so `ALL[k as usize] == k`.
            pub const ALL: &'static [InstructionKind] = &[$(InstructionKind::$variant),+];

            /// How many kinds there are: the width of the profile's counter arrays.
            pub const COUNT: usize = Self::ALL.len();

            pub const fn name(self) -> &'static str {
                match self {
                    $(InstructionKind::$variant => stringify!($variant)),+
                }
            }
        }

        impl<F> Instruction<F> {
            pub const fn kind(&self) -> InstructionKind {
                match self {
                    $(Instruction::$variant(..) => InstructionKind::$variant),+
                }
            }
        }
    };
}

instruction_kinds!(
    BaseAlu,
    ExtAlu,
    Mem,
    Poseidon2,
    Select,
    ExpReverseBitsLen,
    HintBits,
    BatchFRI,
    HintAddCurve,
    Print,
    HintExt2Felts,
    CommitPublicValues,
    Hint,
    AssertZeroExt,
    FracFold,
    UnivariateFold,
    MleOpen,
    LagrangeEvalD2,
    GkrSumcheckRound,
    ExtDotProduct,
    HornerEval,
    DigestSelect,
    BinaryFoldStep,
    PackBlock,
    UnpackBlock,
    Poseidon2Packed,
    ExpBitsLen,
);

impl<F> Instruction<F> {
    /// How many witness blocks this instruction takes off `Runtime::witness_stream`.
    ///
    /// Exhaustive on purpose. `Runtime::run_split` divides the stream between the two children by
    /// counting these ahead of the fork; a new consumer that slipped in under a `_ => 0` arm would
    /// hand each child the other's blocks, which is a different record with no crash and nothing
    /// in the tree to catch it. Adding a variant must not compile until it is classified here.
    pub fn witness_blocks(&self) -> usize {
        match self {
            Instruction::Hint(h) => h.output_addrs_mults.len(),
            Instruction::BaseAlu(_)
            | Instruction::ExtAlu(_)
            | Instruction::Mem(_)
            | Instruction::Poseidon2(_)
            | Instruction::Select(_)
            | Instruction::ExpReverseBitsLen(_)
            | Instruction::HintBits(_)
            | Instruction::BatchFRI(_)
            | Instruction::HintAddCurve(_)
            | Instruction::Print(_)
            | Instruction::HintExt2Felts(_)
            | Instruction::CommitPublicValues(_)
            | Instruction::AssertZeroExt(_)
            | Instruction::FracFold(_)
            | Instruction::UnivariateFold(_)
            | Instruction::MleOpen(_)
            | Instruction::LagrangeEvalD2(_)
            | Instruction::GkrSumcheckRound(_)
            | Instruction::ExtDotProduct(_)
            | Instruction::HornerEval(_)
            | Instruction::DigestSelect(_)
            | Instruction::BinaryFoldStep(_)
            | Instruction::PackBlock(_)
            | Instruction::UnpackBlock(_)
            | Instruction::Poseidon2Packed(_)
            | Instruction::ExpBitsLen(_) => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Instruction<F> {
    BaseAlu(BaseAluInstr<F>),
    ExtAlu(ExtAluInstr<F>),
    Mem(MemInstr<F>),
    Poseidon2(Box<Poseidon2Instr<F>>),
    Select(SelectInstr<F>),
    ExpReverseBitsLen(ExpReverseBitsInstr<F>),
    HintBits(HintBitsInstr<F>),
    BatchFRI(Box<BatchFRIInstr<F>>),
    HintAddCurve(Box<HintAddCurveInstr<F>>),
    Print(PrintInstr<F>),
    HintExt2Felts(HintExt2FeltsInstr<F>),
    CommitPublicValues(Box<CommitPublicValuesInstr<F>>),
    Hint(HintInstr<F>),
    // WHIR verifier chips
    AssertZeroExt(AssertZeroExtInstr<F>),
    FracFold(FracFoldInstr<F>),
    UnivariateFold(Box<UnivariateFoldInstr<F>>),
    MleOpen(MleOpenInstr<F>),
    LagrangeEvalD2(LagrangeEvalD2Instr<F>),
    GkrSumcheckRound(Box<GkrSumcheckRoundInstr<F>>),
    ExtDotProduct(Box<ExtDotProductInstr<F>>),
    HornerEval(Box<HornerEvalInstr<F>>),
    DigestSelect(Box<DigestSelectInstr<F>>),
    BinaryFoldStep(Box<BinaryFoldStepInstr<F>>),
    PackBlock(Box<PackBlockInstr<F>>),
    UnpackBlock(Box<UnpackBlockInstr<F>>),
    Poseidon2Packed(Box<Poseidon2PackedInstr<F>>),
    ExpBitsLen(Box<ExpBitsLenInstr<F>>),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintAddCurveInstr<F> {
    pub output_x_addrs_mults: Vec<(Address<F>, F)>,
    pub output_y_addrs_mults: Vec<(Address<F>, F)>,
    pub input1_x_addrs: Vec<Address<F>>,
    pub input1_y_addrs: Vec<Address<F>>,
    pub input2_x_addrs: Vec<Address<F>>,
    pub input2_y_addrs: Vec<Address<F>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintBitsInstr<F> {
    /// Addresses and mults of the output bits.
    pub output_addrs_mults: Vec<(Address<F>, F)>,
    /// Input value to decompose.
    pub input_addr: Address<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PrintInstr<F> {
    pub field_elt_type: FieldEltType,
    pub addr: Address<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintInstr<F> {
    /// Addresses and mults of the output felts.
    pub output_addrs_mults: Vec<(Address<F>, F)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct HintExt2FeltsInstr<F> {
    /// Addresses and mults of the output bits.
    pub output_addrs_mults: [(Address<F>, F); EXTENSION_DEGREE],
    /// Input value to decompose.
    pub input_addr: Address<F>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FieldEltType {
    Base,
    Extension,
}

pub fn base_alu<F: PrimeCharacteristicRing>(
    opcode: BaseAluOpcode,
    mult: u32,
    out: u32,
    in1: u32,
    in2: u32,
) -> Instruction<F> {
    Instruction::BaseAlu(BaseAluInstr {
        opcode,
        mult: F::from_u32(mult),
        addrs: BaseAluIo {
            out: Address(F::from_u32(out)),
            in1: Address(F::from_u32(in1)),
            in2: Address(F::from_u32(in2)),
        },
    })
}

pub fn ext_alu<F: PrimeCharacteristicRing>(
    opcode: ExtAluOpcode,
    mult: u32,
    out: u32,
    in1: u32,
    in2: u32,
) -> Instruction<F> {
    Instruction::ExtAlu(ExtAluInstr {
        opcode,
        mult: F::from_u32(mult),
        addrs: ExtAluIo {
            out: Address(F::from_u32(out)),
            in1: Address(F::from_u32(in1)),
            in2: Address(F::from_u32(in2)),
        },
    })
}

pub fn mem<F: PrimeCharacteristicRing>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: u32,
) -> Instruction<F> {
    mem_single(kind, mult, addr, F::from_u32(val))
}

pub fn mem_single<F: PrimeCharacteristicRing>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: F,
) -> Instruction<F> {
    mem_block(kind, mult, addr, Block::from(val))
}

pub fn mem_ext<F: PrimeCharacteristicRing + Copy, EF: BasedVectorSpace<F>>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: EF,
) -> Instruction<F> {
    mem_block(kind, mult, addr, val.as_basis_coefficients_slice().into())
}

pub fn mem_block<F: PrimeCharacteristicRing>(
    kind: MemAccessKind,
    mult: u32,
    addr: u32,
    val: Block<F>,
) -> Instruction<F> {
    Instruction::Mem(MemInstr {
        addrs: MemIo {
            inner: Address(F::from_u32(addr)),
        },
        vals: MemIo { inner: val },
        mult: F::from_u32(mult),
        kind,
    })
}

pub fn poseidon2<F: PrimeCharacteristicRing>(
    mults: [u32; WIDTH],
    output: [u32; WIDTH],
    input: [u32; WIDTH],
) -> Instruction<F> {
    Instruction::Poseidon2(Box::new(Poseidon2Instr {
        mults: mults.map(F::from_u32),
        addrs: Poseidon2Io {
            output: output.map(F::from_u32).map(Address),
            input: input.map(F::from_u32).map(Address),
        },
    }))
}

pub fn exp_reverse_bits_len<F: PrimeCharacteristicRing>(
    mult: u32,
    base: F,
    exp: Vec<F>,
    result: F,
) -> Instruction<F> {
    Instruction::ExpReverseBitsLen(ExpReverseBitsInstr {
        mult: F::from_u32(mult),
        addrs: ExpReverseBitsIo {
            base: Address(base),
            exp: exp.into_iter().map(Address).collect(),
            result: Address(result),
        },
    })
}

pub fn commit_public_values<F: PrimeCharacteristicRing>(
    public_values_a: &RecursionPublicValues<u32>,
) -> Instruction<F> {
    let pv_a = public_values_a
        .as_array()
        .map(|pv| Address(F::from_u32(pv)));
    let pv_address: &RecursionPublicValues<Address<F>> = pv_a.as_slice().borrow();

    Instruction::CommitPublicValues(Box::new(CommitPublicValuesInstr {
        pv_addrs: pv_address.clone(),
    }))
}

#[cfg(test)]
mod tests {
    use super::InstructionKind;

    /// The profile indexes its arrays with `kind as usize`; `ALL` is what it iterates to print
    /// them. They agree only while `ALL` is in discriminant order.
    #[test]
    fn kind_discriminants_index_all() {
        for (i, kind) in InstructionKind::ALL.iter().enumerate() {
            assert_eq!(i, *kind as usize, "{} is out of order in ALL", kind.name());
        }
        assert_eq!(InstructionKind::COUNT, InstructionKind::ALL.len());
    }
}
